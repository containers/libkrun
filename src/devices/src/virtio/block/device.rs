// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
use std::path::PathBuf;
use std::result;
use std::sync::Arc;
use std::thread::JoinHandle;

use imago::file::File as ImagoFile;
use imago::qcow2::Qcow2;
use imago::SyncFormatAccess;
use log::{error, warn};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::{
    virtio_blk::*, virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::worker::BlockWorker;
use super::{
    super::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_BLOCK},
    Error, QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE,
};

use crate::virtio::{block::ImageType, ActivateError, InterruptTransport};

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CacheType {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

impl CacheType {
    /// Picks the appropriate cache type based on disk image or device path.
    /// Special files like `/dev/rdisk*` on macOS do not support flush/sync.
    pub fn auto(_path: &str) -> CacheType {
        #[cfg(target_os = "macos")]
        if _path.starts_with("/dev/rdisk") {
            return CacheType::Unsafe;
        }
        CacheType::Writeback
    }
}

/// Helper object for setting up all `Block` fields derived from its backing file.
pub(crate) struct DiskProperties {
    cache_type: CacheType,
    pub(crate) file: Arc<SyncFormatAccess<ImagoFile>>,
    nsectors: u64,
    image_id: Vec<u8>,
}

impl DiskProperties {
    pub fn new(
        disk_image: Arc<SyncFormatAccess<ImagoFile>>,
        disk_image_id: Vec<u8>,
        cache_type: CacheType,
    ) -> io::Result<Self> {
        let disk_size = disk_image.size();

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if disk_size % SECTOR_SIZE != 0 {
            warn!(
                "Disk size {disk_size} is not a multiple of sector size {SECTOR_SIZE}; \
                 the remainder will not be visible to the guest."
            );
        }

        Ok(Self {
            cache_type,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: disk_image_id,
            file: disk_image,
        })
    }

    pub fn file(&self) -> &SyncFormatAccess<ImagoFile> {
        self.file.as_ref()
    }

    pub fn nsectors(&self) -> u64 {
        self.nsectors
    }

    pub fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn build_device_id(disk_file: &File) -> result::Result<String, Error> {
        let blk_metadata = disk_file.metadata().map_err(Error::GetFileMetadata)?;
        // This is how kvmtool does it.
        let device_id = format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        );
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File) -> Vec<u8> {
        let mut default_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(m) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = m.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
            }
        }
        default_id
    }

    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }
}

impl Drop for DiskProperties {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Writeback => {
                // flush() first to force any cached data out.
                if self.file.flush().is_err() {
                    error!("Failed to flush block data on drop.");
                }
                // Sync data out to physical media on host.
                if self.file.sync().is_err() {
                    error!("Failed to sync block data on drop.")
                }
            }
            CacheType::Unsafe => {
                // This is a noop.
            }
        };
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBlkConfig {}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    // Host file and properties.
    disk: Option<DiskProperties>,
    cache_type: CacheType,
    disk_image: Arc<SyncFormatAccess<ImagoFile>>,
    disk_image_id: Vec<u8>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config: VirtioBlkConfig,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: [EventFd; 1],
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) id: String,
    pub(crate) partuuid: Option<String>,
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_image_path: String,
        disk_image_format: ImageType,
        is_disk_read_only: bool,
    ) -> io::Result<Block> {
        let disk_image = OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))?;

        let disk_image_id = DiskProperties::build_disk_image_id(&disk_image);

        let disk_image = match disk_image_format {
            ImageType::Qcow2 => {
                let mut qcow_disk_image =
                    Qcow2::<ImagoFile>::open_path_sync(disk_image_path, !is_disk_read_only)?;
                qcow_disk_image.open_implicit_dependencies_sync()?;
                SyncFormatAccess::new(qcow_disk_image)?
            }
            ImageType::Raw => {
                let raw = imago::raw::Raw::open_path_sync(disk_image_path, !is_disk_read_only)?;
                SyncFormatAccess::new(raw)?
            }
        };
        let disk_image = Arc::new(disk_image);

        let disk_properties =
            DiskProperties::new(Arc::clone(&disk_image), disk_image_id.clone(), cache_type)?;

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BLK_F_FLUSH)
            | (1u64 << VIRTIO_BLK_F_SEG_MAX)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let queue_evts = [EventFd::new(EFD_NONBLOCK)?];

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let config = VirtioBlkConfig {
            capacity: disk_properties.nsectors(),
            size_max: 0,
            // QUEUE_SIZE - 2
            seg_max: 254,
        };

        Ok(Block {
            id,
            partuuid,
            config,
            disk: Some(disk_properties),
            cache_type,
            disk_image,
            disk_image_id,
            avail_features,
            acked_features: 0u64,
            queue_evts,
            queues,
            device_state: DeviceState::Inactive,
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the PARTUUID of this block device.
    pub fn partuuid(&self) -> Option<&String> {
        self.partuuid.as_ref()
    }

    /// Specifies if this block device is read only.
    pub fn is_read_only(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        error!("Guest attempted to write config");
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(&mut self, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> ActivateResult {
        if self.worker_thread.is_some() {
            panic!("virtio_blk: worker thread already exists");
        }

        let event_idx: bool = (self.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        self.queues[0].set_event_idx(event_idx);

        let disk = match self.disk.take() {
            Some(d) => d,
            None => DiskProperties::new(
                Arc::clone(&self.disk_image),
                self.disk_image_id.clone(),
                self.cache_type,
            )
            .map_err(|_| ActivateError::BadActivate)?,
        };

        let worker = BlockWorker::new(
            self.queues[0].clone(),
            self.queue_evts[0].try_clone().unwrap(),
            interrupt.clone(),
            mem.clone(),
            disk,
            self.worker_stopfd.try_clone().unwrap(),
        );
        self.worker_thread = Some(worker.run());

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        self.device_state = DeviceState::Inactive;
        true
    }
}

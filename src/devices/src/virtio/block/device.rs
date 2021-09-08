// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use logger::{error, warn};
use utils::eventfd::EventFd;
use virtio_gen::virtio_blk::*;
use vm_memory::{Bytes, GuestMemoryError, GuestMemoryMmap};

use super::{
    super::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_BLOCK, VIRTIO_MMIO_INT_VRING},
    request::*,
    Error, CONFIG_SPACE_SIZE, QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE,
};

use crate::legacy::Gic;
use crate::virtio::VIRTIO_MMIO_INT_CONFIG;
use crate::Error as DeviceError;

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CacheType {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

impl Default for CacheType {
    fn default() -> CacheType {
        CacheType::Unsafe
    }
}

/// Helper object for setting up all `Block` fields derived from its backing file.
pub(crate) struct DiskProperties {
    cache_type: CacheType,
    file: File,
    nsectors: u64,
    image_id: Vec<u8>,
}

impl DiskProperties {
    pub fn new(
        disk_image_path: String,
        is_disk_read_only: bool,
        cache_type: CacheType,
    ) -> io::Result<Self> {
        let mut disk_image = OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))?;
        let disk_size = disk_image.seek(SeekFrom::End(0))? as u64;

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if disk_size % SECTOR_SIZE != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; \
                 the remainder will not be visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }

        Ok(Self {
            cache_type,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: Self::build_disk_image_id(&disk_image),
            file: disk_image,
        })
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
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

    /// Provides vec containing the virtio block configuration space
    /// buffer. The config space is populated with the disk size based
    /// on the backing file size.
    pub fn virtio_block_config_space(&self) -> Vec<u8> {
        // The config space is little endian.
        let mut config = Vec::with_capacity(CONFIG_SPACE_SIZE);
        for i in 0..CONFIG_SPACE_SIZE {
            config.push((self.nsectors >> (8 * i)) as u8);
        }
        config
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
                if self.file.sync_all().is_err() {
                    error!("Failed to sync block data on drop.")
                }
            }
            CacheType::Unsafe => {
                // This is a noop.
            }
        };
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    // Host file and properties.
    pub(crate) disk: DiskProperties,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config_space: Vec<u8>,
    pub(crate) activate_evt: EventFd,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) interrupt_evt: EventFd,
    pub(crate) queue_evts: [EventFd; 1],
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) id: String,
    pub(crate) partuuid: Option<String>,
    pub(crate) root_device: bool,

    // Interrupt specific fields.
    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
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
        is_disk_read_only: bool,
        is_disk_root: bool,
    ) -> io::Result<Block> {
        let disk_properties = DiskProperties::new(disk_image_path, is_disk_read_only, cache_type)?;

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_BLK_F_FLUSH);

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK)?];

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        Ok(Block {
            id,
            root_device: is_disk_root,
            partuuid,
            config_space: disk_properties.virtio_block_config_space(),
            disk: disk_properties,
            avail_features,
            acked_features: 0u64,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK)?,
            queue_evts,
            queues,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK)?,
            intc: None,
            irq_line: None,
        })
    }

    pub(crate) fn process_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[0].read() {
            error!("Failed to get queue event: {:?}", e);
        } else {
            self.process_virtio_queues();
        }
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) {
        if self.process_queue(0) {
            let _ = self.signal_used_queue();
        }
    }

    pub fn process_queue(&mut self, queue_index: usize) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        let queue = &mut self.queues[queue_index];
        let mut used_any = false;
        while let Some(head) = queue.pop(mem) {
            let len;
            match Request::parse(&head, mem) {
                Ok(request) => {
                    let status = match request.execute(&mut self.disk, mem) {
                        Ok(l) => {
                            // Account for the status byte as well.
                            // With a non-faulty driver, we shouldn't get to the point where we
                            // overflow here (since data len must be a multiple of 512 bytes, so
                            // it can't be u32::MAX). In the future, this should be fixed at the
                            // request parsing level, so no data will actually be transferred in
                            // scenarios like this one.
                            if let Some(l) = l.checked_add(1) {
                                len = l;
                                VIRTIO_BLK_S_OK
                            } else {
                                len = l;
                                VIRTIO_BLK_S_IOERR
                            }
                        }
                        Err(e) => {
                            match e {
                                ExecuteError::Read(GuestMemoryError::PartialBuffer {
                                    completed,
                                    expected,
                                }) => {
                                    error!(
                                        "Failed to execute virtio block read request: can only \
                                        write {} of {} bytes.",
                                        completed, expected
                                    );
                                    // This can not overflow since `completed` < data len which is
                                    // an u32.
                                    len = completed as u32 + 1;
                                }
                                _ => {
                                    error!("Failed to execute virtio block request: {:?}", e);
                                    // Status byte only.
                                    len = 1;
                                }
                            };
                            e.status()
                        }
                    };

                    if let Err(e) = mem.write_obj(status, request.status_addr) {
                        error!("Failed to write virtio block status: {:?}", e)
                    }
                }
                Err(e) => {
                    error!("Failed to parse available descriptor chain: {:?}", e);
                    len = 0;
                }
            }

            queue.add_used(mem, head.index, len);
            used_any = true;
        }

        used_any
    }

    pub(crate) fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        if let Some(intc) = &self.intc {
            intc.lock().unwrap().set_irq(self.irq_line.unwrap());
        } else {
            self.interrupt_evt.write(1).map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })?;
        }
        Ok(())
    }

    /// Update the backing file and the config space of the block device.
    pub fn update_disk_image(&mut self, disk_image_path: String) -> io::Result<()> {
        let disk_properties =
            DiskProperties::new(disk_image_path, self.is_read_only(), self.cache_type())?;
        self.disk = disk_properties;
        self.config_space = self.disk.virtio_block_config_space();

        // Kick the driver to pick up the changes.
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_CONFIG as usize, Ordering::SeqCst);
        if let Some(intc) = &self.intc {
            intc.lock().unwrap().set_irq(self.irq_line.unwrap());
        } else {
            self.interrupt_evt.write(1).unwrap();
        }

        Ok(())
    }

    pub fn set_intc(&mut self, intc: Arc<Mutex<Gic>>) {
        self.intc = Some(intc);
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

    /// Specifies if this block device is read only.
    pub fn is_root_device(&self) -> bool {
        self.root_device
    }

    pub fn cache_type(&self) -> CacheType {
        self.disk.cache_type()
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

    fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    /// Returns the current device interrupt status.
    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn set_irq_line(&mut self, irq: u32) {
        self.irq_line = Some(irq);
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
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_len = self.config_space.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }

        self.config_space[offset as usize..(offset + data_len) as usize].copy_from_slice(data);
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            error!("Block: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}

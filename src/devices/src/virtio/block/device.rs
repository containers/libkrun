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
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use log::{error, warn};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::{
    virtio_blk::*, virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::descriptor_utils::{Reader, Writer};
use super::{
    super::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_BLOCK, VIRTIO_MMIO_INT_VRING},
    Error, CONFIG_SPACE_SIZE, QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE,
};

use crate::legacy::Gic;
use crate::virtio::VIRTIO_MMIO_INT_CONFIG;
use crate::Error as DeviceError;

#[derive(Debug)]
pub enum RequestError {
    FlushingToDisk(io::Error),
    InvalidDataLength,
    ReadingFromDescriptor(io::Error),
    WritingToDescriptor(io::Error),
    UnknownRequest,
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}

// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBlkConfig {}

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
        let disk_size = disk_image.seek(SeekFrom::End(0))?;

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
    config: VirtioBlkConfig,
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
            root_device: is_disk_root,
            partuuid,
            config,
            disk: disk_properties,
            avail_features,
            acked_features: 0u64,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(EFD_NONBLOCK)?,
            queue_evts,
            queues,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(EFD_NONBLOCK)?,
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
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem.clone(),
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        loop {
            self.queues[0].disable_notification(&mem).unwrap();

            self.process_queue(&mem, 0);

            if !self.queues[0].enable_notification(&mem).unwrap() {
                break;
            }
        }
    }

    pub fn process_queue(&mut self, mem: &GuestMemoryMmap, queue_index: usize) {
        while let Some(head) = self.queues[queue_index].pop(mem) {
            let mut reader = match Reader::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {:?}", e);
                    continue;
                }
            };
            let mut writer = match Writer::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {:?}", e);
                    continue;
                }
            };
            let request_header: RequestHeader = match reader.read_obj() {
                Ok(h) => h,
                Err(e) => {
                    error!("invalid request header: {:?}", e);
                    continue;
                }
            };

            let (status, len): (u8, usize) =
                match self.process_request(request_header, &mut reader, &mut writer) {
                    Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                    Err(e) => {
                        error!("error processing request: {:?}", e);
                        (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                    }
                };

            if let Err(e) = writer.write_obj(status) {
                error!("Failed to write virtio block status: {:?}", e)
            }

            if let Err(e) = self.queues[queue_index].add_used(mem, head.index, len as u32) {
                error!("failed to add used elements to the queue: {:?}", e);
            }

            if self.queues[queue_index].needs_notification(mem).unwrap() {
                if let Err(e) = self.signal_used_queue() {
                    error!("error signalling queue: {:?}", e);
                }
            }
        }
    }

    fn process_request(
        &mut self,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer.available_bytes() - 1;
                if data_len % 512 != 0 {
                    return Err(RequestError::InvalidDataLength);
                } else {
                    writer
                        .write_from_at(
                            &self.disk.file,
                            data_len,
                            (request_header.sector * 512) as u64,
                        )
                        .map_err(RequestError::WritingToDescriptor)
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if data_len % 512 != 0 {
                    return Err(RequestError::InvalidDataLength);
                } else {
                    reader
                        .read_to_at(
                            &self.disk.file,
                            data_len,
                            (request_header.sector * 512) as u64,
                        )
                        .map_err(RequestError::ReadingFromDescriptor)
                }
            }
            VIRTIO_BLK_T_FLUSH => match self.disk.cache_type() {
                CacheType::Writeback => {
                    let diskfile = self.disk.file_mut();
                    diskfile.flush().map_err(RequestError::FlushingToDisk)?;
                    diskfile.sync_all().map_err(RequestError::FlushingToDisk)?;
                    Ok(0)
                }
                CacheType::Unsafe => Ok(0),
            },
            VIRTIO_BLK_T_GET_ID => {
                let data_len = writer.available_bytes();
                let disk_id = self.disk.image_id();
                if data_len < disk_id.len() {
                    return Err(RequestError::InvalidDataLength);
                } else {
                    writer
                        .write_all(disk_id)
                        .map_err(RequestError::WritingToDescriptor)?;
                    Ok(disk_id.len())
                }
            }
            _ => Err(RequestError::UnknownRequest),
        }
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
        //self.config_space = self.disk.virtio_block_config_space();

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
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        let event_idx: bool = (self.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        self.queues[0].set_event_idx(event_idx);

        if self.activate_evt.write(1).is_err() {
            error!("Block: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }

    fn reset(&mut self) -> bool {
        // Strictly speaking, we should unsubscribe the queue events resubscribe
        // the activate eventfd and deactivate the device, but we don't support
        // any scenario in which neither GuestMemory nor the queue events would
        // change, so let's avoid doing any unnecessary work.
        self.device_state = DeviceState::Inactive;
        true
    }
}

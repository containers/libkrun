// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::legacy::Gic;
use crate::virtio::net::{Error, Result};
use crate::virtio::net::{QUEUE_SIZES, RX_INDEX, TX_INDEX};
use crate::virtio::queue::Error as QueueError;
use crate::virtio::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_NET};
use crate::Error as DeviceError;

use super::backend::{ReadError, WriteError};
use super::worker::NetWorker;

use std::cmp;
use std::io::Write;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::virtio_net::{
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO,
    VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MAC,
};
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestMemoryError, GuestMemoryMmap};

const VIRTIO_F_VERSION_1: u32 = 32;

#[derive(Debug)]
pub enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    QueueError(QueueError),
    ReadOnlyDescriptor,
}

#[derive(Debug)]
pub enum RxError {
    Backend(ReadError),
    DeviceError(DeviceError),
}

#[derive(Debug)]
pub enum TxError {
    Backend(WriteError),
    DeviceError(DeviceError),
    QueueError(QueueError),
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioNetConfig {}

#[derive(Clone)]
pub enum VirtioNetBackend {
    Passt(RawFd),
    Gvproxy(PathBuf),
}

pub struct Net {
    id: String,
    cfg_backend: VirtioNetBackend,

    avail_features: u64,
    acked_features: u64,

    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,

    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,

    pub(crate) device_state: DeviceState,

    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,

    config: VirtioNetConfig,
}

impl Net {
    /// Create a new virtio network device using the backend
    pub fn new(id: String, cfg_backend: VirtioNetBackend, mac: [u8; 6]) -> Result<Self> {
        let avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_NET_F_MAC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_F_VERSION_1;

        let mut queue_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?);
        }

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let config = VirtioNetConfig {
            mac,
            status: 0,
            max_virtqueue_pairs: 0,
        };

        Ok(Net {
            id,
            cfg_backend,

            avail_features,
            acked_features: 0u64,

            queues,
            queue_evts,

            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?,

            device_state: DeviceState::Inactive,

            intc: None,
            irq_line: None,

            config,
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn set_intc(&mut self, intc: Arc<Mutex<Gic>>) {
        self.intc = Some(intc);
    }
}

impl VirtioDevice for Net {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
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

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn set_irq_line(&mut self, irq: u32) {
        self.irq_line = Some(irq);
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

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        log::warn!(
            "Net: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        let event_idx: bool = (self.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        self.queues[RX_INDEX].set_event_idx(event_idx);
        self.queues[TX_INDEX].set_event_idx(event_idx);

        let queue_evts = self
            .queue_evts
            .iter()
            .map(|e| e.try_clone().unwrap())
            .collect();
        let worker = NetWorker::new(
            self.queues.clone(),
            queue_evts,
            self.interrupt_status.clone(),
            self.interrupt_evt.try_clone().unwrap(),
            self.intc.clone(),
            self.irq_line,
            mem.clone(),
            self.cfg_backend.clone(),
        );
        worker.run();

        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }
}

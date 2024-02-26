// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use utils::byte_order;
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::super::Error as DeviceError;
use super::super::{
    ActivateError, ActivateResult, DeviceState, Queue as VirtQueue, VirtioDevice, VsockError,
    VIRTIO_MMIO_INT_VRING,
};
use super::muxer::VsockMuxer;
use super::packet::VsockPacket;
use super::{defs, defs::uapi};
use crate::legacy::Gic;

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;
pub(crate) const EVQ_INDEX: usize = 2;

/// The virtio features supported by our vsock device:
/// - VIRTIO_F_VERSION_1: the device conforms to at least version 1.0 of the VirtIO spec.
/// - VIRTIO_F_IN_ORDER: the device returns used buffers in the same order that the driver makes
///   them available.
pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64
    | 1 << uapi::VIRTIO_F_IN_ORDER as u64
    | 1 << uapi::VIRTIO_VSOCK_F_DGRAM;

pub struct Vsock {
    cid: u64,
    pub(crate) muxer: VsockMuxer,
    pub(crate) queue_rx: Arc<Mutex<VirtQueue>>,
    pub(crate) queue_tx: Arc<Mutex<VirtQueue>>,
    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) interrupt_evt: EventFd,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
}

impl Vsock {
    pub(crate) fn with_queues(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        queues: Vec<VirtQueue>,
        unix_ipc_port_map: Option<HashMap<u32, PathBuf>>,
    ) -> super::Result<Vsock> {
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events
                .push(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(VsockError::EventFd)?);
        }

        let queue_tx = Arc::new(Mutex::new(queues[TXQ_INDEX].clone()));
        let queue_rx = Arc::new(Mutex::new(queues[RXQ_INDEX].clone()));

        let interrupt_evt =
            EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(VsockError::EventFd)?;
        let interrupt_status = Arc::new(AtomicUsize::new(0));

        Ok(Vsock {
            cid,
            muxer: VsockMuxer::new(
                cid,
                host_port_map,
                interrupt_evt.try_clone().unwrap(),
                interrupt_status.clone(),
                unix_ipc_port_map,
            ),
            queue_rx,
            queue_tx,
            queues,
            queue_events,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            interrupt_status,
            interrupt_evt,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(VsockError::EventFd)?,
            device_state: DeviceState::Inactive,
            intc: None,
            irq_line: None,
        })
    }

    /// Create a new virtio-vsock device with the given VM CID.
    pub fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, PathBuf>>,
    ) -> super::Result<Vsock> {
        let queues: Vec<VirtQueue> = defs::QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(cid, host_port_map, queues, unix_ipc_port_map)
    }

    pub fn id(&self) -> &str {
        defs::VSOCK_DEV_ID
    }

    pub fn set_intc(&mut self, intc: Arc<Mutex<Gic>>) {
        self.intc = Some(intc);
    }

    pub fn cid(&self) -> u64 {
        self.cid
    }

    /// Signal the guest driver that we've used some virtio buffers that it had previously made
    /// available.
    pub fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        debug!("vsock: raising IRQ");
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        if let Some(intc) = &self.intc {
            intc.lock().unwrap().set_irq(self.irq_line.unwrap());
            Ok(())
        } else {
            self.interrupt_evt.write(1).map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
        }
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if descriptors have been added to the used ring, and `false`
    /// otherwise.
    pub fn process_stream_rx(&mut self) -> bool {
        debug!("vsock: process_stream_rx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        debug!("vsock: process_rx before while");
        let mut queue_rx = self.queue_rx.lock().unwrap();
        while let Some(head) = queue_rx.pop(mem) {
            debug!("vsock: process_rx inside while");
            let used_len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => {
                    if self.muxer.recv_pkt(&mut pkt).is_ok() {
                        pkt.hdr().len() as u32 + pkt.len()
                    } else {
                        // We are using a consuming iterator over the virtio buffers, so, if we can't
                        // fill in this buffer, we'll need to undo the last iterator step.
                        queue_rx.undo_pop();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue error: {:?}", e);
                    0
                }
            };

            debug!("vsock: process_rx: something to queue");
            have_used = true;
            if let Err(e) = queue_rx.add_used(mem, head.index, used_len) {
                error!("failed to add used elements to the queue: {:?}", e);
            }
        }

        have_used
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and process
    /// them. Return `true` if descriptors have been added to the used ring, and `false` otherwise.
    pub fn process_stream_tx(&mut self) -> bool {
        debug!("vsock::process_stream_tx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        let mut queue_tx = self.queue_tx.lock().unwrap();
        while let Some(head) = queue_tx.pop(mem) {
            let pkt = match VsockPacket::from_tx_virtq_head(&head) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("vsock: error reading TX packet: {:?}", e);
                    have_used = true;
                    if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                        error!("failed to add used elements to the queue: {:?}", e);
                    }
                    continue;
                }
            };

            if pkt.type_() == uapi::VSOCK_TYPE_DGRAM {
                debug!("vsock::process_stream_tx() is DGRAM");
                if self.muxer.send_dgram_pkt(&pkt).is_err() {
                    queue_tx.undo_pop();
                    break;
                }
            } else {
                debug!("vsock::process_stream_tx() is STREAM");
                if self.muxer.send_stream_pkt(&pkt).is_err() {
                    queue_tx.undo_pop();
                    break;
                }
            }

            have_used = true;
            if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                error!("failed to add used elements to the queue: {:?}", e);
            }
        }

        have_used
    }
}

impl VirtioDevice for Vsock {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_VSOCK
    }

    fn queues(&self) -> &[VirtQueue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [VirtQueue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => byte_order::write_le_u64(data, self.cid()),
            0 if data.len() == 4 => {
                byte_order::write_le_u32(data, (self.cid() & 0xffff_ffff) as u32)
            }
            4 if data.len() == 4 => {
                byte_order::write_le_u32(data, ((self.cid() >> 32) & 0xffff_ffff) as u32)
            }
            _ => warn!(
                "vsock: virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "vsock: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                self.queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.queue_tx = Arc::new(Mutex::new(self.queues[TXQ_INDEX].clone()));
        self.queue_rx = Arc::new(Mutex::new(self.queues[RXQ_INDEX].clone()));
        self.muxer.activate(
            mem.clone(),
            self.queue_rx.clone(),
            self.intc.clone(),
            self.irq_line,
        );

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

// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::legacy::Gic;
use crate::virtio::net::passt::Passt;
use crate::virtio::net::{passt, MAX_BUFFER_SIZE, QUEUE_SIZE, QUEUE_SIZES, RX_INDEX, TX_INDEX};
use crate::virtio::net::{Error, Result};
use crate::virtio::{
    ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_NET, VIRTIO_MMIO_INT_VRING,
};
use crate::Error as DeviceError;
use std::os::fd::RawFd;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::{cmp, mem, result};
use utils::eventfd::EventFd;
use virtio_bindings::virtio_net::{
    virtio_net_hdr_v1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4,
    VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO,
};
use vm_memory::{Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

const VIRTIO_F_VERSION_1: u32 = 32;

#[derive(Debug)]
enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    ReadOnlyDescriptor,
}

#[derive(Debug)]
enum RxError {
    Passt(passt::ReadError),
    DeviceError(DeviceError),
}

#[derive(Debug)]
enum TxError {
    Passt(passt::WriteError),
    DeviceError(DeviceError),
}

pub(crate) fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

// This initializes to all 0 the virtio_net_hdr part of a buf and return the length of the header
// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2050006
fn write_virtio_net_hdr(buf: &mut [u8]) -> usize {
    let len = vnet_hdr_len();
    buf[0..len].fill(0);
    len
}

pub struct Net {
    id: String,
    passt: Passt,

    avail_features: u64,
    acked_features: u64,

    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,

    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    rx_frame_buf_len: usize,
    rx_has_deferred_frame: bool,

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_frame_len: usize,

    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,

    pub(crate) device_state: DeviceState,
    pub(crate) activate_evt: EventFd,

    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
}

impl Net {
    /// Create a new virtio network device using passt
    pub fn new(id: String, passt_fd: RawFd) -> Result<Self> {
        let passt = Passt::new(passt_fd);
        let avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        let mut queue_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
        }

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        Ok(Net {
            id,
            passt,

            avail_features,
            acked_features: 0u64,

            queues,
            queue_evts,

            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,

            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),

            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,

            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,

            intc: None,
            irq_line: None,
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[RX_INDEX].read() {
            log::error!("Failed to get rx event from queue: {:?}", e);
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by queue event)")
        };
    }

    pub(crate) fn process_tx_queue_event(&mut self) {
        match self.queue_evts[TX_INDEX].read() {
            Ok(_) => {
                if let Err(e) = self.process_tx() {
                    log::error!("Failed to process tx event: {e:?}");
                };
            }
            Err(e) => {
                log::error!("Failed to get tx queue event from queue: {e:?}");
            }
        }
    }

    pub(crate) fn process_passt_socket_readable(&mut self) {
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by passt socket readable)");
        };
    }

    pub(crate) fn process_passt_socket_writeable(&mut self) {
        match self
            .passt
            .try_finish_write(vnet_hdr_len(), &self.tx_frame_buf[..self.tx_frame_len])
        {
            Ok(()) => {
                if let Err(e) = self.process_tx() {
                    log::error!("Failed to continue processing tx after passt socket was writable again: {e:?}");
                }
            }
            Err(passt::WriteError::PartialWrite | passt::WriteError::NothingWritten) => {}
            Err(e @ passt::WriteError::Internal(_)) => {
                log::error!("Failed to finish write: {e:?}");
            }
            Err(e @ passt::WriteError::ProcessNotRunning) => {
                log::debug!("Failed to finish write: {e:?}");
            }
        }
    }

    pub(crate) fn raw_passt_socket_fd(&self) -> RawFd {
        self.passt.raw_socket_fd()
    }

    fn process_rx(&mut self) -> result::Result<(), RxError> {
        // if we have a deferred frame we try to process it first,
        // if that is not possible, we don't continue processing other frames
        if self.rx_has_deferred_frame {
            if self.write_frame_to_guest() {
                self.rx_has_deferred_frame = false;
            } else {
                return Ok(());
            }
        }

        let mut signal_queue = false;

        // Read as many frames as possible.
        let result = loop {
            match self.read_into_rx_frame_buf_from_passt() {
                Ok(()) => {
                    if self.write_frame_to_guest() {
                        signal_queue = true;
                    } else {
                        self.rx_has_deferred_frame = true;
                        break Ok(());
                    }
                }
                Err(passt::ReadError::NothingRead) => break Ok(()),
                Err(e @ passt::ReadError::Internal(_)) => break Err(RxError::Passt(e)),
            }
        };

        // At this point we processed as many Rx frames as possible.
        // We have to wake the guest if at least one descriptor chain has been used.
        if signal_queue {
            self.signal_used_queue().map_err(RxError::DeviceError)?;
        }

        result
    }

    fn process_tx(&mut self) -> result::Result<(), TxError> {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let tx_queue = &mut self.queues[TX_INDEX];

        if self.passt.has_unfinished_write()
            && self
                .passt
                .try_finish_write(vnet_hdr_len(), &self.tx_frame_buf[..self.tx_frame_len])
                .is_err()
        {
            log::trace!("Cannot process tx because of unfinished partial write!");
            return Ok(());
        }

        let mut raise_irq = false;

        while let Some(head) = tx_queue.pop(mem) {
            let head_index = head.index;
            let mut read_count = 0;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    self.tx_iovec.clear();
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                read_count += desc.len as usize;
                next_desc = desc.next_descriptor();
            }

            // Copy buffer from across multiple descriptors.
            read_count = 0;
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min(read_count + desc_len, self.tx_frame_buf.len());

                let read_result =
                    mem.read_slice(&mut self.tx_frame_buf[read_count..limit], desc_addr);
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        log::error!("Failed to read slice: {:?}", e);
                        read_count = 0;
                        break;
                    }
                }
            }

            self.tx_frame_len = read_count;
            match self
                .passt
                .write_frame(vnet_hdr_len(), &mut self.tx_frame_buf[..read_count])
            {
                Ok(()) => {
                    self.tx_frame_len = 0;
                    tx_queue.add_used(mem, head_index, 0);
                    raise_irq = true;
                }
                Err(passt::WriteError::NothingWritten) => {
                    tx_queue.undo_pop();
                    break;
                }
                Err(passt::WriteError::PartialWrite) => {
                    log::trace!("process_tx: partial write");
                    /*
                    This situation should be pretty rare, assuming reasonably sized socket buffers.
                    We have written only a part of a frame to the passt socket (the socket is full).

                    The frame we have read from the guest remains in tx_frame_buf, and will be sent
                    later.

                    Note that we cannot wait for passt to process our sending frames, because passt
                    could be blocked on sending a remainder of a frame to us - us waiting for passt
                    would cause a deadlock.
                     */
                    tx_queue.add_used(mem, head_index, 0);
                    raise_irq = true;
                    break;
                }
                Err(
                    e @ passt::WriteError::Internal(_) | e @ passt::WriteError::ProcessNotRunning,
                ) => return Err(TxError::Passt(e)),
            }
        }

        if raise_irq {
            self.signal_used_queue().map_err(TxError::DeviceError)?;
        }

        Ok(())
    }

    fn signal_used_queue(&mut self) -> result::Result<(), DeviceError> {
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

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn write_frame_to_guest_impl(&mut self) -> result::Result<(), FrontendError> {
        let mut result: std::result::Result<(), FrontendError> = Ok(());
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let queue = &mut self.queues[RX_INDEX];
        let head_descriptor = queue.pop(mem).ok_or_else(|| FrontendError::EmptyQueue)?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_frame_buf_len];

        let frame_len = frame_slice.len();
        let mut maybe_next_descriptor = Some(head_descriptor);
        while let Some(descriptor) = &maybe_next_descriptor {
            if frame_slice.is_empty() {
                break;
            }

            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }

            let len = std::cmp::min(frame_slice.len(), descriptor.len as usize);
            match mem.write_slice(&frame_slice[..len], descriptor.addr) {
                Ok(()) => {
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    log::error!("Failed to write slice: {:?}", e);
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            };

            maybe_next_descriptor = descriptor.next_descriptor();
        }
        if result.is_ok() && !frame_slice.is_empty() {
            log::warn!("Receiving buffer is too small to hold frame of current size");
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue.add_used(mem, head_index, used_len);

        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. In case of an error retries
    // the operation if possible. Returns true if the operation was successfull.
    fn write_frame_to_guest(&mut self) -> bool {
        let max_iterations = self.queues[RX_INDEX].actual_size();
        for _ in 0..max_iterations {
            match self.write_frame_to_guest_impl() {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) => {
                    return false;
                }
                Err(_) => {
                    // retry
                    continue;
                }
            }
        }

        false
    }

    /// Fills self.rx_frame_buf with an ethernet frame from passt and prepends virtio_net_hdr to it
    fn read_into_rx_frame_buf_from_passt(&mut self) -> result::Result<(), passt::ReadError> {
        let mut len = 0;
        len += write_virtio_net_hdr(&mut self.rx_frame_buf);
        len += self.passt.read_frame(&mut self.rx_frame_buf[len..])?;
        self.rx_frame_buf_len = len;
        Ok(())
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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        log::warn!(
            "Net: guest driver attempted to read device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        log::warn!(
            "Net: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            log::error!("Net: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
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

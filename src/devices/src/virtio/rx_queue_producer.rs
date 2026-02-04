// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RX queue provider for batched virtio receive operations.

use std::io::IoSliceMut;

use smallvec::SmallVec;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};

use super::queue::{DescriptorChain, Queue};
use super::InterruptTransport;

/// A pending descriptor chain with its state.
struct PendingChain {
    head_index: u16,
    max_bytes: usize,
    bytes_used: usize,
    finished: bool,
}

/// RxQueueProducer - owns the RX queue and provides buffers for receiving.
///
/// Pops descriptor chains from the virtio RX queue and provides writable
/// iovecs for receiving data. Unfinished chains are kept pending for the next
/// produce() call; finished chains get add_used() with their byte counts.
pub struct RxQueueProducer {
    /// The virtio RX queue (owned)
    queue: Queue,
    /// Guest memory reference
    mem: GuestMemoryMmap,
    /// Interrupt for signaling guest
    interrupt: InterruptTransport,

    /// Pending chains with their state
    pending_chains: SmallVec<[PendingChain; 32]>,
    /// Writable iovecs for each pending descriptor chain
    pending_iovecs: SmallVec<[SmallVec<[IoSliceMut<'static>; 4]>; 32]>,
}

/// Completer for reporting received bytes per chain.
pub struct RxCompleter<'a> {
    pending_chains: &'a mut [PendingChain],
    queue: &'a mut Queue,
    mem: &'a GuestMemoryMmap,
}

/// Advance iovecs in place by `bytes`, removing fully consumed buffers.
fn advance_iovecs<'a>(iovecs: &mut SmallVec<[IoSliceMut<'a>; 4]>, bytes: usize) {
    let mut remaining = bytes;
    while remaining > 0 && !iovecs.is_empty() {
        let first_len = iovecs[0].len();
        if first_len <= remaining {
            iovecs.remove(0);
            remaining -= first_len;
        } else {
            let first = &mut iovecs[0];
            let ptr = first.as_mut_ptr();
            let new_len = first_len - remaining;
            // Safety: advancing pointer within same allocation
            let new_slice = unsafe { std::slice::from_raw_parts_mut(ptr.add(remaining), new_len) };
            iovecs[0] = IoSliceMut::new(new_slice);
            remaining = 0;
        }
    }
}

impl RxCompleter<'_> {
    /// Number of pending chains.
    #[inline]
    pub fn len(&self) -> usize {
        self.pending_chains.len()
    }

    /// Get bytes already received for chain at index.
    #[inline]
    pub fn bytes_used(&self, index: usize) -> usize {
        self.pending_chains[index].bytes_used
    }

    /// Get maximum bytes the chain can hold.
    #[inline]
    pub fn max_bytes(&self, index: usize) -> usize {
        self.pending_chains[index].max_bytes
    }

    /// Advance bytes used for chain at index (partial receive).
    ///
    /// Also advances the iovecs in place, removing consumed buffers.
    /// Chain remains pending for next produce() call.
    pub fn advance<'b>(
        &mut self,
        iovecs: &mut SmallVec<[IoSliceMut<'b>; 4]>,
        index: usize,
        bytes: usize,
    ) {
        let chain = &mut self.pending_chains[index];
        chain.bytes_used += bytes;
        debug_assert!(
            chain.bytes_used <= chain.max_bytes,
            "advance: bytes_used {} exceeds max_bytes {}",
            chain.bytes_used,
            chain.max_bytes
        );
        advance_iovecs(iovecs, bytes);
    }

    /// Mark chain at index as finished.
    ///
    /// Chain will be removed and add_used called after callback returns.
    /// Can be called out-of-order.
    pub fn finish(&mut self, index: usize) {
        let chain = &mut self.pending_chains[index];
        if chain.finished {
            return;
        }
        chain.finished = true;
        log::trace!(
            "RxCompleter::finish: index={} head_index={} bytes_used={}",
            index,
            chain.head_index,
            chain.bytes_used
        );
        if let Err(e) = self.queue.add_used(self.mem, chain.head_index, chain.bytes_used as u32) {
            log::error!("RxCompleter: failed to add_used: {e}");
        }
    }

    /// Convenience: advance bytes and finish in one call.
    pub fn complete<'b>(
        &mut self,
        iovecs: &mut SmallVec<[IoSliceMut<'b>; 4]>,
        index: usize,
        bytes: usize,
    ) {
        self.advance(iovecs, index, bytes);
        self.finish(index);
    }
}


impl RxQueueProducer {
    /// Create a new RxQueueProvider with the given queue, memory, and interrupt.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> Self {
        Self {
            queue,
            mem,
            interrupt,
            pending_chains: SmallVec::new(),
            pending_iovecs: SmallVec::new(),
        }
    }

    /// Number of chains currently pending (ready for receive).
    pub fn pending_count(&self) -> usize {
        self.pending_chains.len()
    }

    /// Feed descriptor chains from queue up to max_frames.
    ///
    /// Returns the number of new frames added.
    pub fn feed(&mut self, max_frames: usize) -> usize {
        self.feed_with_transform(max_frames, |_iovecs| {
            // No transformation
        })
    }

    /// Feed descriptor chains from queue, applying callback to each.
    ///
    /// The callback receives mutable iovecs from the descriptor chain and can:
    /// - Write header data (e.g., vnet header for RX)
    /// - Skip bytes by advancing iovecs in place
    ///
    /// This is useful for prepending headers that the guest expects but the
    /// network backend doesn't provide.
    ///
    /// Returns the number of frames added.
    pub fn feed_with_transform<F>(&mut self, max_frames: usize, mut transform: F) -> usize
    where
        F: for<'a> FnMut(&mut SmallVec<[IoSliceMut<'a>; 4]>),
    {
        let mut added = 0;

        while self.pending_count() < max_frames {
            let Some(head) = self.queue.pop(&self.mem) else {
                break;
            };

            let head_index = head.index;
            // Safety: The 'static lifetime here is a lie - the slices actually point into
            // `self.mem`. This is safe because:
            // 1. `self` owns `mem`, so the memory outlives these iovecs
            // 2. The iovecs are stored in `self.pending_iovecs` (requires 'static for storage)
            // 3. The HRTB `for<'a>` on callbacks erases the 'static before user code sees it
            // 4. All access goes through `produce()` which borrows `&mut self`, preventing
            //    use-after-free (can't drop self while iovecs are in use)
            let mut iovecs: SmallVec<[IoSliceMut<'static>; 4]> = SmallVec::new();
            let mut valid = true;

            for desc in head.into_iter() {
                // Only process writable descriptors (guest-writable = receive buffer)
                if desc.is_write_only() {
                    if let Some(iov) = self.desc_to_ioslice_mut(&desc) {
                        iovecs.push(iov);
                    } else {
                        log::error!(
                            "RxQueueProvider: failed to map descriptor addr={:x} len={}",
                            desc.addr.raw_value(),
                            desc.len
                        );
                        valid = false;
                        break;
                    }
                }
            }

            if !valid || iovecs.is_empty() {
                // Invalid or empty - mark as used with 0 bytes
                if let Err(e) = self.queue.add_used(&self.mem, head_index, 0) {
                    log::error!("RxQueueProvider: failed to add_used: {e}");
                }
                continue;
            }

            let max_bytes: usize = iovecs.iter().map(|iov| iov.len()).sum();

            // Apply transformation (e.g., write vnet header and advance iovecs)
            transform(&mut iovecs);

            self.pending_chains.push(PendingChain {
                head_index,
                max_bytes,
                bytes_used: 0,
                finished: false,
            });
            self.pending_iovecs.push(iovecs);
            added += 1;
        }

        added
    }

    /// Convert a descriptor to a mutable IoSlice pointing into guest memory.
    fn desc_to_ioslice_mut(&self, desc: &DescriptorChain) -> Option<IoSliceMut<'static>> {
        let len = desc.len as usize;
        let slice = self.mem.get_slice(desc.addr, len).ok()?;
        let ptr = slice.ptr_guard_mut().as_ptr();

        // Safety: We own the GuestMemoryMmap, so the memory is valid for our lifetime.
        let byte_slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
        let static_slice: &'static mut [u8] = unsafe { std::mem::transmute(byte_slice) };
        
        Some(IoSliceMut::new(static_slice))
    }

    /// Produce frames by calling the callback with chains and a completer.
    ///
    /// The callback receives iovecs (already advanced by previous calls to advance())
    /// and an RxCompleter to mark chains as used. Returns the number of chains finished.
    pub fn produce<F>(&mut self, f: F) -> usize
    where
        F: for<'a> FnOnce(&mut [SmallVec<[IoSliceMut<'a>; 4]>], &mut RxCompleter<'_>),
    {
        if self.pending_chains.is_empty() {
            return 0;
        }

        {
            let mut completer = RxCompleter {
                pending_chains: &mut self.pending_chains,
                queue: &mut self.queue,
                mem: &self.mem,
            };
            f(&mut self.pending_iovecs, &mut completer);
        }

        // Remove finished chains (can be out-of-order, so remove all marked finished)
        let mut finished_count = 0;
        let mut i = 0;
        while i < self.pending_chains.len() {
            if self.pending_chains[i].finished {
                self.pending_chains.remove(i);
                self.pending_iovecs.remove(i);
                finished_count += 1;
            } else {
                i += 1;
            }
        }

        if finished_count > 0 {
            self.signal_used_if_needed();
        }

        finished_count
    }

    /// Signal used queue interrupt if needed.
    fn signal_used_if_needed(&mut self) {
        match self.queue.needs_notification(&self.mem) {
            Ok(true) => {
                log::trace!("RxQueueProducer: signaling used queue interrupt");
                self.interrupt.signal_used_queue();
            }
            Ok(false) => {
                log::trace!("RxQueueProducer: needs_notification returned false, not signaling");
            }
            Err(e) => {
                log::error!("RxQueueProvider: needs_notification error: {e}");
            }
        }
    }

    /// Get the raw queue for direct access.
    pub fn queue(&self) -> &Queue {
        &self.queue
    }

    /// Get mutable queue reference for notification control.
    pub fn queue_mut(&mut self) -> &mut Queue {
        &mut self.queue
    }

    /// Get memory reference.
    pub fn mem(&self) -> &GuestMemoryMmap {
        &self.mem
    }
}

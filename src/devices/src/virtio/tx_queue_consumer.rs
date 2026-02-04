// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TX queue consumer for batched virtio transmit operations.

use std::io::IoSlice;

use smallvec::SmallVec;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};

use super::iovec_utils::iovecs_len;
use super::queue::{DescriptorChain, Queue};
use super::InterruptTransport;

/// Result of a consume callback - indicates how much was consumed.
#[derive(Debug, Clone, Copy)]
pub enum Consumed {
    /// Number of bytes consumed (e.g., from writev return value)
    Bytes(usize),
    /// Number of complete descriptor chains consumed (e.g., from sendmmsg return value)
    Chains(usize),
}

/// Metadata for a frame in the batch - tracks origin for add_used()
#[derive(Debug, Clone, Copy)]
struct FrameMeta {
    /// Descriptor chain head index for queue.add_used()
    head_index: u16,
    /// Total bytes in iovecs (for I/O completion tracking)
    total_len: usize,
    /// Bytes from guest descriptors (for add_used reporting)
    guest_len: usize,
}

/// TxQueueConsumer - owns the TX queue and manages frame batching.
///
/// Generic abstraction: pulls descriptor chains from virtio queue,
/// applies a user-provided callback to transform each chain into iovecs,
/// batches results, handles add_used() after send.
///
/// # Safety
///
/// The iovecs stored in `frame_iovecs` point into guest memory owned by `mem`.
/// The lifetime is erased to 'static because the struct owns the memory reference.
/// This is safe as long as:
/// 1. The struct outlives any use of the iovecs
/// 2. The guest memory is not unmapped while iovecs are in use
pub struct TxQueueConsumer {
    /// The virtio TX queue (owned)
    queue: Queue,
    /// Guest memory reference
    mem: GuestMemoryMmap,
    /// Interrupt for signaling guest
    interrupt: InterruptTransport,

    /// Per-frame iovecs (outer vec = frames, inner = iovecs per frame)
    /// Safety: these point into `mem` which is owned by this struct
    frame_iovecs: SmallVec<[SmallVec<[IoSlice<'static>; 4]>; 32]>,
    /// Metadata for each frame (parallel to frame_iovecs)
    frame_meta: SmallVec<[FrameMeta; 32]>,
    // TODO: Implement a proper HeaderAllocator that the feed() callback can use to safely
    // allocate header bytes and get IoSlice<'static> references. The allocator would:
    // 1. Use a pre-reserved Vec<u8> buffer to prevent reallocation
    // 2. Provide an alloc(&[u8]) -> IoSlice<'static> method
    // 3. Handle the unsafe lifetime extension internally
    // For now, we use Box::leak in the callback code as a temporary workaround.

    /// Number of frames fully sent
    sent_frames: usize,
    /// Bytes consumed from the first pending frame (for partial write tracking)
    partial_bytes: usize,
}

impl TxQueueConsumer {
    /// Create a new TxQueueConsumer with the given queue, memory, and interrupt.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> Self {
        Self {
            queue,
            mem,
            interrupt,
            frame_iovecs: SmallVec::new(),
            frame_meta: SmallVec::new(),
            sent_frames: 0,
            partial_bytes: 0,
        }
    }

    /// Feed descriptor chains from queue (simple version).
    ///
    /// This is the common case - just sums the byte count of each chain.
    /// For advanced use cases (e.g., inserting headers), use `feed_with_transform`.
    pub fn feed(&mut self, max_frames: usize) -> usize {
        self.feed_with_transform(max_frames, |_iovecs| {
            // No transformation - lengths computed automatically
        })
    }

    /// Feed descriptor chains from queue, applying callback to each.
    ///
    /// The callback receives mutable iovecs from the descriptor chain and can:
    /// - Skip bytes (e.g., vnet header) by using `IoSlice::advance_slices`
    /// - Insert header iovecs (e.g., frame length for stream sockets)
    /// - Modify data in place
    ///
    /// Returns the number of frames added to the batch.
    ///
    /// # Arguments
    /// * `max_frames` - Maximum frames to feed (including already pending)
    /// * `transform` - Callback to transform each descriptor chain's iovecs
    ///
    /// The callback can transform the iovecs (skip bytes, add headers, etc).
    /// Both the original chain length (for add_used) and the final length
    /// (for completion tracking) are computed automatically.
    ///
    pub fn feed_with_transform<F>(&mut self, max_frames: usize, mut transform_chain: F) -> usize
    where
        F: for<'a> FnMut(&mut SmallVec<[IoSlice<'a>; 4]>),
    {
        let mut added = 0;

        while self.pending_count() < max_frames {
            let Some(head) = self.queue.pop(&self.mem) else {
                break;
            };
            let head_index = head.index;

            // Build iovecs from descriptor chain.
            //
            // Safety: The 'static lifetime here is a lie - the slices actually point into
            // `self.mem`. This is safe because:
            // 1. `self` owns `mem`, so the memory outlives these iovecs
            // 2. The iovecs are stored in `self.frame_iovecs` (requires 'static for storage)
            // 3. The HRTB `for<'a>` on callbacks erases the 'static before user code sees it
            // 4. All access goes through `consume()` which borrows `&mut self`, preventing
            //    use-after-free (can't drop self while iovecs are in use)
            let mut iovecs: SmallVec<[IoSlice<'static>; 4]> = SmallVec::new();
            let mut valid = true;

            for desc in head.into_iter() {
                // Only process readable descriptors (guest-readable = data to send)
                if desc.is_read_only() {
                    if let Some(iov) = self.desc_to_ioslice(&desc) {
                        iovecs.push(iov);
                    } else {
                        log::error!(
                            "TxQueueConsumer: failed to map descriptor addr={:x} len={}",
                            desc.addr.raw_value(),
                            desc.len
                        );
                        valid = false;
                        break;
                    }
                }
            }

            if !valid || iovecs.is_empty() {
                // Invalid or empty descriptor chain - mark as used with 0 bytes
                if let Err(e) = self.queue.add_used(&self.mem, head_index, 0) {
                    log::error!("TxQueueConsumer: failed to add_used: {e}");
                }
                continue;
            }

            // Compute original chain length before transformation
            let guest_len = iovecs_len(&iovecs);

            // Apply user callback to transform iovecs
            transform_chain(&mut iovecs);

            // Compute final length after transformation
            let total_len = iovecs_len(&iovecs);

            self.frame_iovecs.push(iovecs);
            self.frame_meta.push(FrameMeta {
                head_index,
                total_len,
                guest_len,
            });
            added += 1;
        }

        added
    }

    /// Convert a descriptor to an IoSlice pointing into guest memory.
    ///
    /// Returns None if the descriptor's memory region cannot be found or mapped.
    ///
    /// # Safety
    /// The returned IoSlice has 'static lifetime but actually points into `self.mem`.
    /// This is safe because `self` owns `mem` and the IoSlice won't outlive `self`.
    fn desc_to_ioslice(&self, desc: &DescriptorChain) -> Option<IoSlice<'static>> {
        let len = desc.len as usize;
        let slice = self.mem.get_slice(desc.addr, len).ok()?;
        let ptr = slice.ptr_guard_mut().as_ptr();

        // Safety: We own the GuestMemoryMmap, so the memory is valid for our lifetime.
        // The slice points into pinned guest memory that won't move.
        let byte_slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        // Transmute to 'static - safe because we own the memory reference
        let static_slice: &'static [u8] = unsafe { std::mem::transmute(byte_slice) };

        Some(IoSlice::new(static_slice))
    }

    /// Number of frames pending (not yet sent)
    pub fn pending_count(&self) -> usize {
        self.frame_meta.len() - self.sent_frames
    }

    /// Check if there are any pending frames
    pub fn has_pending(&self) -> bool {
        self.pending_count() > 0
    }

    /// Consume pending chains using a callback that performs the actual I/O.
    ///
    /// The callback receives the chain iovecs and returns `Ok(Consumed::Bytes(n))`
    /// or `Ok(Consumed::Chains(n))` to indicate how much was consumed.
    ///
    // TODO: Switch to a completer pattern like rx_queue_producer uses, where the
    // callback receives a completer object to mark chains as complete.
    ///
    /// The consumer then:
    /// - Advances by the returned amount (completing chains as appropriate)
    /// - Calls add_used() for completed chains
    /// - Signals interrupt if needed
    /// - Compacts internal buffers
    ///
    /// On error (e.g., EAGAIN), pending chains are kept for retry later.
    pub fn consume<F, E>(&mut self, f: F) -> Result<Consumed, E>
    where
        F: for<'a> FnOnce(&[SmallVec<[IoSlice<'a>; 4]>]) -> Result<Consumed, E>,
    {
        if !self.has_pending() {
            return Ok(Consumed::Chains(0));
        }

        match f(&self.frame_iovecs[self.sent_frames..]) {
            Ok(consumed) => {
                match consumed {
                    Consumed::Bytes(bytes) => self.advance_bytes(bytes),
                    Consumed::Chains(count) => self.advance_chains(count),
                }
                self.compact();
                Ok(consumed)
            }
            Err(e) => Err(e),
        }
    }

    /// Advance by N complete chains (e.g., from sendmmsg return value).
    ///
    /// Calls add_used() for each completed chain and signals interrupt.
    pub fn advance_chains(&mut self, count: usize) {
        for _ in 0..count {
            if self.sent_frames >= self.frame_meta.len() {
                break;
            }
            let meta = &self.frame_meta[self.sent_frames];
            if let Err(e) = self.queue.add_used(&self.mem, meta.head_index, meta.guest_len as u32) {
                log::error!("TxQueueConsumer: failed to add_used: {e}");
            }
            self.sent_frames += 1;
        }
        self.signal_used_if_needed();
    }

    /// Advance by N bytes, completing chains as bytes are consumed.
    ///
    /// Calls add_used() for completed chains and signals interrupt.
    pub fn advance_bytes(&mut self, bytes: usize) {
        self.partial_bytes += bytes;

        // Complete frames while we have enough bytes
        while self.sent_frames < self.frame_meta.len() {
            let meta = &self.frame_meta[self.sent_frames];
            if self.partial_bytes >= meta.total_len {
                if let Err(e) = self.queue.add_used(&self.mem, meta.head_index, meta.guest_len as u32) {
                    log::error!("TxQueueConsumer: failed to add_used: {e}");
                }
                self.partial_bytes -= meta.total_len;
                self.sent_frames += 1;
            } else {
                break;
            }
        }

        self.signal_used_if_needed();
    }

    /// Clear completed frames from buffers.
    ///
    /// Call this after processing to free memory from completed frames.
    /// Note: `partial_bytes` is preserved - it tracks bytes consumed from the
    /// first pending frame (now at index 0 after compact).
    pub fn compact(&mut self) {
        if self.sent_frames > 0 {
            self.frame_iovecs.drain(..self.sent_frames);
            self.frame_meta.drain(..self.sent_frames);
            self.sent_frames = 0;
        }
    }

    /// Signal used queue interrupt if needed.
    fn signal_used_if_needed(&mut self) {
        match self.queue.needs_notification(&self.mem) {
            Ok(true) => self.interrupt.signal_used_queue(),
            Ok(false) => {} // No notification needed
            Err(e) => {
                log::error!("TxQueueConsumer: needs_notification error: {e}");
            }
        }
    }

    /// Get the raw queue for direct access (e.g., for enable/disable_notification).
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

// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RX queue producer for batched virtio receive operations.

use std::io::IoSliceMut;
use std::ops::Range;

use libc::iovec;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};

use super::chain_storage::{AdvanceBytes, ChainsMemoryRepr, IovecVec, TruncateBytes};
use super::iovec_utils::write_to_iovecs;
use super::queue::{DescriptorChain, Queue};
use super::InterruptTransport;

/// Metadata for a pending descriptor chain.
#[derive(Debug)]
struct ChainMeta<M: Default> {
    head_index: u16,
    max_bytes: usize,
    bytes_used: usize,
    finished: bool,
    /// User-defined metadata from representation (e.g., Vec capacity for mmsghdr)
    user_meta: M,
}

/// RxQueueProducer - owns the RX queue and provides buffers for receiving.
///
/// Generic over representation type R, allowing different backends to use optimized
/// representations (e.g., mmsghdr for recvmmsg). Default is IovecVec.
///
/// Pops descriptor chains from the virtio RX queue and provides writable
/// iovecs for receiving data. Unfinished chains are kept pending for the next
/// produce() call; finished chains get add_used() with their byte counts.
///
/// The iovecs point into guest memory owned by `mem`. This is safe because
/// the struct owns the memory reference and outlives any use of the iovecs.
pub struct RxQueueProducer<R: ChainsMemoryRepr = IovecVec> {
    /// The virtio RX queue
    queue: Queue,
    /// Guest memory reference
    mem: GuestMemoryMmap,
    /// Interrupt for signaling guest
    interrupt: InterruptTransport,

    /// Per-chain representation (type depends on R)
    chain_repr: Vec<R>,
    /// Metadata for each chain (parallel to chain_repr)
    chain_meta: Vec<ChainMeta<R::Meta>>,
}

/// Batch for producing RX chains.
///
/// Provides access to pending chains and methods to mark them as complete.
/// Panics if you access or finish an already-finished chain.
pub struct RxProducerBatch<'a, R: ChainsMemoryRepr> {
    chain_repr: &'a mut [R],
    chain_meta: &'a mut [ChainMeta<R::Meta>],
    queue: &'a mut Queue,
    mem: &'a GuestMemoryMmap,
    /// Index of first unfinished chain. Chains 0..first_unfinished are finished.
    /// For sequential finishing (0, 1, 2...), this advances efficiently.
    first_unfinished: usize,
}

impl<R: ChainsMemoryRepr> RxProducerBatch<'_, R> {
    /// Number of pending chains.
    #[inline]
    pub fn len(&self) -> usize {
        self.chain_repr.len()
    }

    /// Returns true if there are no pending chains.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.chain_repr.is_empty()
    }

    /// Get mutable access to a chain's representation by index.
    ///
    /// This is useful for backends that need to access representation-specific features
    /// (e.g., getting mmsghdr from MsgHdrRx representation).
    ///
    /// # Panics
    ///
    /// Panics if index is out of bounds or if the chain has already been finished.
    pub fn chain_mut(&mut self, index: usize) -> &mut R {
        assert!(
            !self.chain_meta[index].finished,
            "chain_mut: chain at index {} already finished",
            index
        );
        &mut self.chain_repr[index]
    }

    /// Get mutable access to chains in a range (checked).
    ///
    /// Returns a mutable slice of chain representation for the given range.
    /// Optimized for sequential finishing: if `range.start >= first_unfinished`,
    /// all chains in range are guaranteed unfinished (O(1) check).
    ///
    /// # Panics
    ///
    /// Panics if any chain in the range has already been finished.
    pub fn chains_mut(&mut self, range: Range<usize>) -> &mut [R] {
        // Fast path: if range starts at or after first_unfinished, all are unfinished
        if range.start < self.first_unfinished {
            // Slow path: range may include finished chains, check each
            for i in range.clone() {
                assert!(
                    !self.chain_meta[i].finished,
                    "all_chains_mut: chain at index {} already finished",
                    i
                );
            }
        }
        &mut self.chain_repr[range]
    }

    /// Get mutable access to chains in a range (unchecked).
    ///
    /// # Safety
    ///
    /// This provides unchecked access to representations including already-finished
    /// chains. The caller must ensure they only access valid (non-finished) chains.
    #[inline]
    pub unsafe fn chains_mut_unchecked(&mut self, range: Range<usize>) -> &mut [R] {
        self.chain_repr.get_unchecked_mut(range)
    }

    /// Get bytes already received for chain at index.
    #[inline]
    pub fn bytes_used(&self, index: usize) -> usize {
        self.chain_meta[index].bytes_used
    }

    /// Get maximum bytes the chain can hold.
    #[inline]
    pub fn max_bytes(&self, index: usize) -> usize {
        self.chain_meta[index].max_bytes
    }

    /// Mark chain at index as finished.
    ///
    /// Calls add_used immediately. Chain will be removed after callback returns.
    /// Can be called out-of-order, but sequential finishing (0, 1, 2...) is
    /// optimized via `first_unfinished` tracking.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn finish(&mut self, index: usize) {
        let meta = &mut self.chain_meta[index];
        assert!(
            !meta.finished,
            "finish: chain at index {} already finished",
            index
        );
        meta.finished = true;
        log::info!(
            "RxProducerBatch::finish: index={} head_index={} bytes_used={}",
            index,
            meta.head_index,
            meta.bytes_used
        );
        if let Err(e) = self
            .queue
            .add_used(self.mem, meta.head_index, meta.bytes_used as u32)
        {
            log::error!("RxProducerBatch: failed to add_used: {e}");
        }

        // Update first_unfinished for sequential finishing optimization
        if index == self.first_unfinished {
            // Scan forward to find next unfinished chain
            while self.first_unfinished < self.chain_meta.len()
                && self.chain_meta[self.first_unfinished].finished
            {
                self.first_unfinished += 1;
            }
        }
    }

    /// Complete a chain with the given byte count.
    ///
    /// Updates bytes_used and marks the chain as finished.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn complete(&mut self, index: usize, bytes: usize) {
        self.chain_meta[index].bytes_used += bytes;
        self.finish(index);
    }
}

/// Methods for representation types that support advancing (for partial receives).
impl<R: ChainsMemoryRepr + AdvanceBytes> RxProducerBatch<'_, R> {
    /// Advance bytes used for chain at index (partial receive).
    ///
    /// Updates bytes_used and advances the iovecs in place.
    /// Chain remains pending for next produce() call.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn advance(&mut self, index: usize, bytes: usize) {
        assert!(
            !self.chain_meta[index].finished,
            "advance: chain at index {} already finished",
            index
        );
        let meta = &mut self.chain_meta[index];
        meta.bytes_used += bytes;
        debug_assert!(
            meta.bytes_used <= meta.max_bytes,
            "advance: bytes_used {} exceeds max_bytes {}",
            meta.bytes_used,
            meta.max_bytes
        );
        self.chain_repr[index].advance(bytes);
    }
}

/// Methods for representation types that support truncating (limiting receive size).
impl<R: ChainsMemoryRepr + TruncateBytes> RxProducerBatch<'_, R> {
    /// Truncate chain at index to limit receive to `max_bytes`.
    ///
    /// This is useful when you know the frame size ahead of time and want to
    /// limit how much data can be received into the buffer.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn truncate(&mut self, index: usize, max_bytes: usize) {
        assert!(
            !self.chain_meta[index].finished,
            "truncate: chain at index {} already finished",
            index
        );
        self.chain_repr[index].truncate_bytes(max_bytes);
    }
}

/// Specialized methods for the default IovecVec representation type.
impl RxProducerBatch<'_, IovecVec> {
    /// Get a chain's iovecs as mutable IoSliceMut references.
    ///
    /// # Panics
    ///
    /// Panics if index is out of bounds or if the chain has already been finished.
    pub fn io_slices_mut(&mut self, index: usize) -> &mut [IoSliceMut<'_>] {
        assert!(
            !self.chain_meta[index].finished,
            "io_slices_mut: chain at index {} already finished",
            index
        );
        let slice = &mut self.chain_repr[index].0[..];
        // The lifetime is tied to &mut self, ensuring the iovecs remain valid.
        unsafe { std::slice::from_raw_parts_mut(slice.as_mut_ptr().cast(), slice.len()) }
    }

    /// Write data to chain and advance bytes_used (without finishing).
    ///
    /// Useful for writing headers (e.g., vnet header for RX) before receiving
    /// the actual payload.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if the chain doesn't have enough space for all the data.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    #[allow(clippy::result_unit_err)]
    pub fn write_advance(&mut self, index: usize, data: &[u8]) -> Result<(), ()> {
        let written = write_to_iovecs(self.io_slices_mut(index), data);
        if written != data.len() {
            return Err(());
        }
        self.advance(index, written);
        Ok(())
    }

    /// Write data to chain and complete it.
    ///
    /// Writes the data, advances bytes_used, and finishes the chain in one call.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if the chain doesn't have enough space for all the data.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    #[allow(clippy::result_unit_err)]
    pub fn write_complete(&mut self, index: usize, data: &[u8]) -> Result<(), ()> {
        let written = write_to_iovecs(self.io_slices_mut(index), data);
        if written != data.len() {
            return Err(());
        }
        self.complete(index, written);
        Ok(())
    }
}

impl<R: ChainsMemoryRepr> RxQueueProducer<R> {
    /// Create a new RxQueueProducer with the given queue, memory, and interrupt.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> Self {
        Self {
            queue,
            mem,
            interrupt,
            chain_repr: Vec::new(),
            chain_meta: Vec::new(),
        }
    }

    /// Number of chains currently pending (ready for receive).
    pub fn pending_count(&self) -> usize {
        self.chain_meta.len()
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
    ///
    /// # Arguments
    /// * `max_frames` - Maximum frames to feed (including already pending)
    /// * `transform` - Callback to transform each descriptor chain's iovecs
    ///
    /// # Lifetime Note
    /// The callback uses HRTB to hide the internal 'static lifetime. The iovecs
    /// point into guest memory owned by this struct - do not store references.
    pub fn feed_with_transform<F>(&mut self, max_frames: usize, mut transform: F) -> usize
    where
        F: for<'a> FnMut(Vec<IoSliceMut<'a>>) -> (R, R::Meta),
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
            // 2. The iovecs are stored in chain_repr (requires 'static for representation)
            // 3. All access goes through `produce()` which borrows `&mut self`, preventing
            //    use-after-free (can't drop self while iovecs are in use)
            let mut iovecs: Vec<IoSliceMut<'static>> = Vec::new();
            let mut valid = true;

            for desc in head.into_iter() {
                // Only process writable descriptors (guest-writable = receive buffer)
                if desc.is_write_only() {
                    if let Some(iov) = self.desc_to_ioslice_mut(&desc) {
                        iovecs.push(iov);
                    } else {
                        log::error!(
                            "RxQueueProducer: failed to map descriptor addr={:x} len={}",
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
                    log::error!("RxQueueProducer: failed to add_used: {e}");
                }
                continue;
            }

            // Compute original chain length before transformation
            let max_bytes: usize = iovecs.iter().map(|iov| iov.len()).sum();

            // Apply transformation (callback takes ownership, returns representation)
            let (storage, user_meta) = transform(iovecs);

            // Track bytes consumed by transform (header written + advanced)
            let transform_bytes = max_bytes - storage.total_bytes();

            self.chain_repr.push(storage);
            self.chain_meta.push(ChainMeta {
                head_index,
                max_bytes,
                bytes_used: transform_bytes,
                finished: false,
                user_meta,
            });
            added += 1;
        }

        added
    }

    /// Convert a descriptor to a mutable IoSlice pointing into guest memory.
    ///
    /// Returns None if the descriptor's memory region cannot be found or mapped.
    ///
    /// # Safety
    /// The returned IoSliceMut has 'static lifetime but actually points into `self.mem`.
    /// This is safe because `self` owns `mem` and the IoSliceMut won't outlive `self`.
    fn desc_to_ioslice_mut(&self, desc: &DescriptorChain) -> Option<IoSliceMut<'static>> {
        let len = desc.len as usize;
        let slice = self.mem.get_slice(desc.addr, len).ok()?;
        let ptr = slice.ptr_guard_mut().as_ptr();

        // Safety: We own the GuestMemoryMmap, so the memory is valid for our lifetime.
        // The slice points into pinned guest memory that won't move.
        let byte_slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };

        // Transmute to 'static - safe because we own the memory reference
        let static_slice: &'static mut [u8] = unsafe { std::mem::transmute(byte_slice) };

        Some(IoSliceMut::new(static_slice))
    }

    /// Produce frames by calling the callback with a batch.
    ///
    /// The callback receives an `RxProducerBatch` which provides access to chains
    /// and methods to mark them as complete. Returns the number of chains finished.
    pub fn produce<F>(&mut self, f: F) -> usize
    where
        F: for<'a> FnOnce(&mut RxProducerBatch<'a, R>),
    {
        if self.chain_meta.is_empty() {
            log::info!("RxQueueProducer::produce: no chains pending, returning 0");
            return 0;
        }

        log::info!(
            "RxQueueProducer::produce: {} chains pending, calling callback",
            self.chain_meta.len()
        );

        {
            let mut batch = RxProducerBatch {
                chain_repr: &mut self.chain_repr,
                chain_meta: &mut self.chain_meta,
                queue: &mut self.queue,
                mem: &self.mem,
                first_unfinished: 0,
            };
            f(&mut batch);
        }

        // Remove finished chains in O(n) by swapping unfinished to front, then truncating
        let mut finished_count = 0;
        let mut write = 0;
        for read in 0..self.chain_meta.len() {
            if self.chain_meta[read].finished {
                self.chain_repr[read].clear(&mut self.chain_meta[read].user_meta);
                finished_count += 1;
            } else {
                if write != read {
                    self.chain_repr.swap(write, read);
                    self.chain_meta.swap(write, read);
                }
                write += 1;
            }
        }
        self.chain_repr.truncate(write);
        self.chain_meta.truncate(write);

        log::info!(
            "RxQueueProducer::produce: finished_count={} remaining={}",
            finished_count,
            write
        );

        if finished_count > 0 {
            self.signal_used_if_needed();
        }

        finished_count
    }

    /// Signal used queue interrupt if needed.
    fn signal_used_if_needed(&mut self) {
        match self.queue.needs_notification(&self.mem) {
            Ok(true) => {
                log::info!("RxQueueProducer: signaling used queue interrupt");
                self.interrupt.signal_used_queue();
            }
            Ok(false) => {
                log::info!("RxQueueProducer: needs_notification returned false, not signaling");
            }
            Err(e) => {
                log::error!("RxQueueProducer: needs_notification error: {e}");
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

/// Convenience methods for the default representation type (IovecVec).
impl RxQueueProducer<IovecVec> {
    /// Feed descriptor chains from queue without transformation.
    ///
    /// This is a convenience method for the common case where no header
    /// transformation is needed.
    pub fn feed(&mut self, max_frames: usize) -> usize {
        self.feed_with_transform(max_frames, |iovecs| {
            let raw: Vec<iovec> = unsafe { std::mem::transmute(iovecs) };
            (IovecVec(raw), ())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::IoSliceMut;

    use crate::virtio::chain_storage::IovecVec;
    use crate::virtio::iovec_utils::{advance_iovecs_vec, write_to_iovecs};
    use crate::virtio::test_utils::{
        create_interrupt, create_memory, create_test_queue, ExpectedUsed, VirtQueueDriver,
    };

    use super::RxQueueProducer;

    /// Helper type alias for tests using default representation
    type TestRxProducer = RxQueueProducer;

    /// Helper to convert IoSliceMut to IovecVec (for test callbacks)
    fn to_iovec(iovecs: Vec<IoSliceMut<'_>>) -> IovecVec {
        IovecVec(unsafe { std::mem::transmute(iovecs) })
    }

    #[test]
    fn test_new_producer_is_empty() {
        let mem = create_memory();
        let queue = create_test_queue();
        let _driver = VirtQueueDriver::new(&queue, &mem);
        let producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        assert_eq!(producer.pending_count(), 0);
    }

    #[test]
    fn test_feed_single_writable_descriptor() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = producer.feed(10);

        assert_eq!(added, 1);
        assert_eq!(producer.pending_count(), 1);
    }

    #[test]
    fn test_feed_chained_writable_descriptors() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        // Chain of 2 writable descriptors
        driver.writable(&[512, 1024]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = producer.feed(10);

        assert_eq!(added, 1);
        assert_eq!(producer.pending_count(), 1);

        // Verify buffer structure via produce
        producer.produce(|batch| {
            assert_eq!(batch.len(), 1);
            let chain = batch.io_slices_mut(0);
            assert_eq!(chain.len(), 2);
            assert_eq!(chain[0].len(), 512);
            assert_eq!(chain[1].len(), 1024);
            // Don't mark anything as finished
        });
    }

    #[test]
    fn test_feed_multiple_buffers() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        // 3 separate single-descriptor chains
        driver.writable(&[1500]).writable(&[1500]).writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = producer.feed(10);

        assert_eq!(added, 3);
        assert_eq!(producer.pending_count(), 3);
    }

    #[test]
    fn test_feed_respects_max_frames() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = producer.feed(2);

        assert_eq!(added, 2);
        assert_eq!(producer.pending_count(), 2);
    }

    #[test]
    fn test_produce_fills_buffers() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.writable(&[1500]).writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);
        assert_eq!(producer.pending_count(), 2);

        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"Received packet 1").unwrap();
            batch.write_complete(1, b"Received packet 2").unwrap();
        });

        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 0);

        // Verify add_used was called with actual bytes written (17), not buffer capacity (1500)
        // Also verifies the content written to guest memory
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"Received packet 1")),
            (1, ExpectedUsed::Writable(b"Received packet 2")),
        ]);
    }

    #[test]
    fn test_produce_partial_fill() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.writable(&[1500]).writable(&[1500]).writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);

        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"0123456789").unwrap();
            batch.write_complete(1, b"ABCDEFGHIJ").unwrap();
            // Third not filled - don't call complete
        });

        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 1);

        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"0123456789")),
            (1, ExpectedUsed::Writable(b"ABCDEFGHIJ")),
        ]);
    }

    #[test]
    fn test_produce_keeps_unused_buffers() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.writable(&[1500]).writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);

        // First produce: no data received (EAGAIN-like)
        let completed = producer.produce(|_batch| {
            // Don't complete anything
        });
        assert_eq!(completed, 0);
        assert_eq!(producer.pending_count(), 2);

        // Second produce: fill one buffer
        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"Hello").unwrap();
            // Don't complete second buffer
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 1);

        driver.assert_used(&[(0, ExpectedUsed::Writable(b"Hello"))]);
    }

    #[test]
    fn test_empty_queue_returns_zero() {
        let mem = create_memory();
        let queue = create_test_queue();
        let _driver = VirtQueueDriver::new(&queue, &mem);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        assert_eq!(producer.feed(10), 0);
        assert_eq!(producer.pending_count(), 0);
        assert_eq!(producer.produce(|_batch| {}), 0);
    }

    #[test]
    fn test_skips_read_only_descriptors() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        // Chain with readable then writable (readable should be skipped for RX)
        driver.readable_then_writable(&[b"ignored"], &[1400]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);

        // Verify buffer structure via produce
        producer.produce(|batch| {
            assert_eq!(batch.len(), 1);
            let chain = batch.io_slices_mut(0);
            assert_eq!(chain.len(), 1);
            assert_eq!(chain[0].len(), 1400);
        });
    }

    #[test]
    fn test_chained_buffer_receive() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        // Chain of 3 writable descriptors forming one buffer
        driver.writable(&[100, 200, 300]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);
        assert_eq!(producer.pending_count(), 1);

        let completed = producer.produce(|batch| {
            let mut data = vec![0xAA; 100];
            data.extend(vec![0xBB; 200]);
            data.extend(vec![0xCC; 300]);
            batch.write_complete(0, &data).unwrap();
        });

        assert_eq!(completed, 1);

        // Verify add_used reports 600 bytes and content matches
        // Chain has 3 segments: 100 bytes of 0xAA, 200 bytes of 0xBB, 300 bytes of 0xCC
        let mut expected_data = vec![0xAA; 100];
        expected_data.extend(vec![0xBB; 200]);
        expected_data.extend(vec![0xCC; 300]);
        driver.assert_used(&[(0, ExpectedUsed::Writable(&expected_data))]);
    }

    #[test]
    fn test_multiple_produce_cycles() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        // Create 4 chains, each with 3 descriptors: [6, 12, 6] = 24 bytes total
        // After 2-byte header skip: [4, 12, 6] = 22 bytes usable
        driver
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        // First feed: get 2 buffers, skip 2-byte header from each
        let added = producer.feed_with_transform(2, |mut iovecs| {
            // Write 2-byte header, then advance past it
            write_to_iovecs(&mut iovecs, b"HD");
            advance_iovecs_vec(&mut iovecs, 2);
            (to_iovec(iovecs), ())
        });
        assert_eq!(added, 2);
        assert_eq!(producer.pending_count(), 2);

        // First produce:
        // - Chain 0: write "AAAABBBBBBBBBBBBCC" (18 bytes) spanning all 3 iovecs, complete
        // - Chain 1: write "XXXX" (4 bytes), partial advance, don't complete
        // Note: header bytes are automatically tracked by feed_with_transform
        let completed = producer.produce(|batch| {
            // Chain 0: spans [4, 12, 2] of the available [4, 12, 6]
            batch.write_complete(0, b"AAAABBBBBBBBBBBBCC").unwrap();

            // Chain 1: partial write, just 4 bytes into first iovec
            let written = write_to_iovecs(batch.io_slices_mut(1), b"XXXX");
            assert_eq!(written, 4);
            batch.advance(1, 4);
            // Don't complete - leave pending
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 1);

        // Second feed: get 1 more (1 pending + 1 new = 2)
        let added = producer.feed_with_transform(2, |mut iovecs| {
            write_to_iovecs(&mut iovecs, b"HD");
            advance_iovecs_vec(&mut iovecs, 2);
            (to_iovec(iovecs), ())
        });
        assert_eq!(added, 1);
        assert_eq!(producer.pending_count(), 2);

        // Second produce:
        // - Chain 0 (was chain 1): iovecs already advanced, write "YYYYYYYY" (8 more), complete
        // - Chain 1 (chain 2): fresh chain, write spanning iovecs, complete
        let completed = producer.produce(|batch| {
            // Chain 0: continue after previous 4 bytes, write 8 more
            // Use write_to_iovecs + complete since we already have partial bytes_used
            let written = write_to_iovecs(batch.io_slices_mut(0), b"YYYYYYYY");
            assert_eq!(written, 8);
            batch.complete(0, 8); // adds to existing bytes_used

            // Chain 1: fresh chain, write spanning first 2 iovecs
            batch.write_complete(1, b"ZZZZZZZZZZZZ").unwrap(); // 12 bytes: fills [4] + 8 of [12]
        });
        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 0);

        // Verify used ring:
        // Chain 0: "HD" (header) + "AAAABBBBBBBBBBBBCC" (18 bytes) = 20 bytes total
        // Chain 1: "HD" (header) + "XXXXYYYYYYYY" (12 bytes) = 14 bytes total
        // Chain 2: "HD" (header) + "ZZZZZZZZZZZZ" (12 bytes) = 14 bytes total
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDAAAABBBBBBBBBBBBCC")),
            (1, ExpectedUsed::Writable(b"HDXXXXYYYYYYYY")),
            (2, ExpectedUsed::Writable(b"HDZZZZZZZZZZZZ")),
        ]);
    }

    #[test]
    fn test_selective_completion() {
        // Verify that only explicitly completed chains are removed.
        // With the new API, completion is explicit via batch.finish().
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.writable(&[1500]).writable(&[1500]).writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);
        assert_eq!(producer.pending_count(), 3);

        // Complete only buffer 0, leave 1 and 2 pending
        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"pkt0").unwrap();
            // Don't complete buffers 1 and 2
        });

        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 2); // buffers 1 and 2 kept

        driver.assert_used(&[(0, ExpectedUsed::Writable(b"pkt0"))]);
    }
}

// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TX queue consumer for batched virtio transmit operations.

use std::io::IoSlice;
use std::ops::Range;

use libc::iovec;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};

use super::chain_storage::{AdvanceBytes, ChainsMemoryRepr, IovecVec};
use super::queue::{DescriptorChain, Queue};
use super::InterruptTransport;

/// Metadata for a pending descriptor chain.
#[derive(Debug, Clone)]
struct ChainMeta<M: Default> {
    head_index: u16,
    /// Total bytes in iovecs (for I/O completion tracking)
    max_bytes: usize,
    /// Bytes from guest descriptors (for add_used reporting)
    guest_len: usize,
    /// Bytes sent so far (for partial send tracking)
    bytes_used: usize,
    finished: bool,
    /// User-defined metadata
    user_meta: M,
}

/// Batch for consuming TX chains.
///
/// Provides access to pending chains and methods to mark them as complete.
/// Supports both chain-based completion (whole messages) and byte-based
/// completion (for backends that track partial progress).
///
/// Panics if you access or complete an already-completed chain.
pub struct TxConsumerBatch<'a, R: ChainsMemoryRepr> {
    chain_repr: &'a mut [R],
    chain_meta: &'a mut [ChainMeta<R::Meta>],
    queue: &'a mut Queue,
    mem: &'a GuestMemoryMmap,
    /// Index of first uncompleted chain. Chains 0..first_finished are completed.
    /// For sequential completion, this equals the number of completed chains.
    first_finished: usize,
}

impl<R: ChainsMemoryRepr> TxConsumerBatch<'_, R> {
    /// Number of pending chains in this batch.
    #[inline]
    pub fn len(&self) -> usize {
        self.chain_repr.len()
    }
    
    /// Check if chain is already finished.
    #[inline]
    pub fn is_finished(&self, index: usize) -> bool {
        self.chain_meta[index].finished
    }

    /// Get bytes already consumed for chain at index.
    #[inline]
    pub fn bytes_used(&self, index: usize) -> usize {
        self.chain_meta[index].bytes_used
    }

    /// Get maximum bytes the chain can hold.
    #[inline]
    pub fn max_bytes(&self, index: usize) -> usize {
        self.chain_meta[index].max_bytes
    }

    /// Get access to a chain at index.
    ///
    /// # Panics
    ///
    /// Panics if index is out of bounds or if the chain has already been completed.
    pub fn chain(&self, index: usize) -> &R {
        self.assert_not_finished(index);
        &self.chain_repr[index]
    }

    /// Get access to chains in a range (checked).
    ///
    /// Returns a slice of chain representations for the given range.
    ///
    /// O(1) if chains are being finished sequentially, O(n) otherwise.
    ///
    /// # Panics
    ///
    /// Panics if any chain in the range has already been completed.
    pub fn chains(&self, range: Range<usize>) -> &[R] {
        // Fast path: if range starts at or after first_finished, all are uncompleted
        if range.start < self.first_finished {
            // Slow path: range may include completed chains, check each
            for i in range.clone() {
                self.assert_not_finished(i);
            }
        }
        &self.chain_repr[range]
    }

    /// Mark chain at index as complete.
    ///
    /// Calls add_used immediately. Chain will be removed after consume() returns.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been completed.
    pub fn complete(&mut self, index: usize) {
        self.finish(index);
    }

    /// Mark range of chains as complete.
    ///
    /// # Panics
    ///
    /// Panics if any chain in the range has already been completed.
    pub fn complete_many(&mut self, range: Range<usize>) {
        for i in range {
            self.complete(i);
        }
    }

    /// Get total bytes across all pending (non-completed) chains.
    pub fn total_bytes(&self) -> usize {
        self.chain_meta
            .iter()
            .filter(|m| !m.finished)
            .map(|m| m.max_bytes)
            .sum()
    }

    /// Mark chain at index as finished.
    ///
    /// Calls add_used immediately. Chain will be removed after consume() returns.
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
        log::trace!(
            "finish: index={} head_index={} guest_len={}",
            index,
            meta.head_index,
            meta.guest_len
        );
        if let Err(e) = self
            .queue
            .add_used(self.mem, meta.head_index, meta.guest_len as u32)
        {
            log::error!("TxConsumerBatch: failed to add_used: {e}");
        }

        // Update first_finished for sequential completion optimization
        if index == self.first_finished {
            while self.first_finished < self.chain_meta.len()
                && self.chain_meta[self.first_finished].finished
            {
                self.first_finished += 1;
            }
        }
    }
    
    #[track_caller]
    fn assert_not_finished(&self, index: usize) {
        assert!(
            !self.is_finished(index),
            "chain at index {index} already finished",
        );
    }
}

/// Methods for representation types that support advancing (for partial sends).
impl<R: ChainsMemoryRepr + AdvanceBytes> TxConsumerBatch<'_, R> {
    /// Advance bytes used for chain at index (partial send).
    ///
    /// Updates bytes_used and advances the iovecs in place.
    /// Chain remains pending for next consume() call.
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
        self.chain_meta[index].bytes_used += bytes;
        self.chain_repr[index].advance(bytes);
    }
}

/// Specialized methods for the default IovecVec representation type.
impl TxConsumerBatch<'_, IovecVec> {
    /// Get a chain's iovecs as IoSlice references.
    ///
    /// # Panics
    ///
    /// Panics if index is out of bounds or if the chain has already been finished.
    pub fn io_slices(&self, index: usize) -> &[IoSlice<'_>] {
        assert!(
            !self.chain_meta[index].finished,
            "io_slices: chain at index {} already completed",
            index
        );
        let slice = &self.chain_repr[index].0[..];
        // iovec and IoSlice have the same memory layout
        unsafe { std::slice::from_raw_parts(slice.as_ptr().cast(), slice.len()) }
    }
}

/// TxQueueConsumer - owns the TX queue and manages chain batching.
///
/// Generic over representation type R, allowing different backends to use optimized
/// representations (e.g., mmsghdr for sendmmsg). Default is IovecVec.
///
/// The iovecs stored in chain representation point into guest memory owned by `mem`.
/// This is safe because the struct owns the memory reference and outlives any
/// use of the iovecs.
pub struct TxQueueConsumer<R: ChainsMemoryRepr = IovecVec> {
    /// The virtio TX queue (owned)
    queue: Queue,
    /// Guest memory reference
    mem: GuestMemoryMmap,
    /// Interrupt for signaling guest
    interrupt: InterruptTransport,

    /// Per-chain representation (type depends on R)
    chain_repr: Vec<R>,
    /// Metadata for each chain (parallel to chain_repr)
    chain_meta: Vec<ChainMeta<R::Meta>>,

    /// Number of chains fully sent
    sent_chains: usize,
}

impl<R: ChainsMemoryRepr> TxQueueConsumer<R> {
    /// Create a new TxQueueConsumer with the given queue, memory, and interrupt.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> Self {
        Self {
            queue,
            mem,
            interrupt,
            chain_repr: Vec::new(),
            chain_meta: Vec::new(),
            sent_chains: 0,
        }
    }

    /// Feed descriptor chains from queue, applying callback to transform each.
    ///
    /// The callback receives the iovecs from the descriptor chain and can:
    /// - Transform the iovecs (skip bytes, add headers, etc.)
    /// - Return the representation and metadata
    ///
    /// Returns the number of chains added to the batch.
    ///
    /// # Arguments
    /// * `max_chains` - Maximum chains to feed (including already pending)
    /// * `transform` - Callback that takes iovecs and returns (representation, meta)
    pub fn feed_with_transform<F>(&mut self, max_chains: usize, mut transform: F) -> usize
    where
        F: for<'a> FnMut(Vec<IoSlice<'a>>) -> (R, R::Meta),
    {
        let mut added = 0;

        'next_chain: while self.pending_count() < max_chains {
            let Some(head) = self.queue.pop(&self.mem) else {
                // Queue exhausted: re-enable driver kicks. If more descriptors arrived in the
                // meantime, loops back to pop them; otherwise break and wait for the next kick.
                match self.queue.enable_notification(&self.mem) {
                    Ok(true) => continue 'next_chain,
                    _ => break 'next_chain,
                }
            };
            let head_index = head.index;

            let mut iovecs: Vec<IoSlice<'_>> = Vec::new();
            let mut valid = true;

            for desc in head.into_iter().filter(DescriptorChain::is_read_only) {
                if let Some(iov) = self.desc_to_ioslice(&desc) {
                    iovecs.push(iov);
                } else {
                    log::warn!(
                        "Invalid descriptor head_index={} addr={:x} len={}, skipping the chain",
                        head_index,
                        desc.addr.raw_value(),
                        desc.len
                    );
                    continue 'next_chain;
                }
            }

            if iovecs.is_empty() {
                warn!("Found empty chain, ignoring it");
                continue 'next_chain;
            }

            // Compute original chain length before transformation
            let guest_len: usize = iovecs.iter().map(|s| s.len()).sum();

            // Apply transformation (callback takes ownership, returns representation)
            let (repr, user_meta) = transform(iovecs);

            // Compute final length from storage
            let max_bytes = repr.total_bytes();
            
            // Track bytes consumed by transform (header written + advanced)
            let bytes_used = max_bytes - repr.total_bytes();

            self.chain_repr.push(repr);
            self.chain_meta.push(ChainMeta {
                head_index,
                max_bytes,
                guest_len,
                bytes_used,
                finished: false,
                user_meta,
            });
            added += 1;
        }

        added
    }

    /// Convert a descriptor to an IoSlice pointing into guest memory.
    ///
    /// Returns None if the descriptor's memory region cannot be found or mapped.
    fn desc_to_ioslice(&self, desc: &DescriptorChain) -> Option<IoSlice<'_>> {
        let len = desc.len as usize;
        let slice = self.mem.get_slice(desc.addr, len).ok()?;
        let ptr = slice.ptr_guard_mut().as_ptr();

        // Safety: We own the GuestMemoryMmap, so the memory is valid for our lifetime.
        let byte_slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        Some(IoSlice::new(byte_slice))
    }

    /// Number of chains pending (not yet sent)
    pub fn pending_count(&self) -> usize {
        self.chain_meta.len() - self.sent_chains
    }

    /// Check if there are any pending chains
    pub fn has_pending(&self) -> bool {
        self.pending_count() > 0
    }

    /// Consume pending chains using a callback that performs the actual I/O.
    ///
    /// The callback receives a `TxConsumerBatch` which provides:
    /// - `chain(i)` - access to chain iovecs by index (panics if already completed)
    /// - `complete_chains(n)` - mark first N chains as complete
    /// - `complete_bytes(n)` - mark chains complete based on byte count
    ///
    /// Returns the number of chains completed. Completed chains are removed
    /// from the pending list and interrupt is signaled if needed.
    pub fn consume<F>(&mut self, f: F) -> usize
    where
        F: for<'a> FnOnce(&mut TxConsumerBatch<'a, R>),
    {
        if !self.has_pending() {
            return 0;
        }

        let completed_count;
        {
            let pending_storage = &mut self.chain_repr[self.sent_chains..];
            let pending_meta = &mut self.chain_meta[self.sent_chains..];

            let mut batch = TxConsumerBatch {
                chain_repr: pending_storage,
                chain_meta: pending_meta,
                queue: &mut self.queue,
                mem: &self.mem,
                first_finished: 0,
            };

            f(&mut batch);
            completed_count = batch.first_finished;
        }

        // Update sent_chains based on what was completed
        self.sent_chains += completed_count;

        if completed_count > 0 {
            self.signal_used_if_needed();
        }

        self.compact();
        completed_count
    }

    /// Clear completed chains from buffers.
    ///
    /// Call this after processing to free memory from completed chains.
    /// Note: `partial_bytes` is preserved - it tracks bytes consumed from the
    /// first pending chain (now at index 0 after compact).
    pub fn compact(&mut self) {
        if self.sent_chains > 0 {
            // Clear representation properly (calls R::clear with meta)
            for i in 0..self.sent_chains {
                self.chain_repr[i].clear(&mut self.chain_meta[i].user_meta);
            }
            self.chain_repr.drain(..self.sent_chains);
            self.chain_meta.drain(..self.sent_chains);
            self.sent_chains = 0;
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

/// Convenience methods for the default representation type (IovecVec).
impl TxQueueConsumer<IovecVec> {
    /// Feed descriptor chains from queue without transformation.
    ///
    /// This is a convenience method for the common case where no header
    /// transformation is needed.
    pub fn feed(&mut self, max_chains: usize) -> usize {
        self.feed_with_transform(max_chains, |iovecs| {
            let raw: Vec<iovec> = unsafe { std::mem::transmute(iovecs) };
            (IovecVec(raw), ())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::IoSlice;

    use crate::virtio::chain_storage::IovecVec;
    use crate::virtio::test_utils::{
        create_interrupt, create_memory, create_test_queue, ExpectedUsed, VirtQueueDriver,
    };

    use super::TxQueueConsumer;

    /// Helper type alias for tests using default representation
    type TestTxConsumer = TxQueueConsumer;

    /// Helper to convert IoSlice to IovecVec (for test callbacks)
    fn to_iovec(iovecs: Vec<IoSlice<'_>>) -> IovecVec {
        IovecVec(unsafe { std::mem::transmute(iovecs) })
    }

    #[test]
    fn test_new_consumer_is_empty() {
        let mem = create_memory();
        let queue = create_test_queue();
        let consumer: TestTxConsumer = TxQueueConsumer::new(queue, mem.clone(), create_interrupt());

        assert_eq!(consumer.pending_count(), 0);
        assert!(!consumer.has_pending());
    }

    #[test]
    fn test_feed_single_descriptor() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.readable(&[b"Hello, World!"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed(10);

        assert_eq!(added, 1);
        assert_eq!(consumer.pending_count(), 1);
        assert!(consumer.has_pending());

        // Verify chain content via consume callback
        let completed = consumer.consume(|batch| {
            assert_eq!(batch.len(), 1);
            assert_eq!(batch.io_slices(0).len(), 1);
            assert_eq!(&*batch.io_slices(0)[0], b"Hello, World!");
            batch.complete(0);
        });

        assert_eq!(completed, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable(13))]);
    }

    #[test]
    fn test_feed_chained_descriptors() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        // Chain of two descriptors
        driver.readable(&[b"First", b"Second"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed(10);

        assert_eq!(added, 1);
        assert_eq!(consumer.pending_count(), 1);

        let completed = consumer.consume(|batch| {
            assert_eq!(batch.io_slices(0).len(), 2);
            assert_eq!(&*batch.io_slices(0)[0], b"First");
            assert_eq!(&*batch.io_slices(0)[1], b"Second");
            batch.complete(0);
        });

        assert_eq!(completed, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable(11))]);
    }

    #[test]
    fn test_feed_multiple_frames() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .readable(&[b"Frame1"])
            .readable(&[b"Frame2"])
            .readable(&[b"Frame3"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed(10);

        assert_eq!(added, 3);
        assert_eq!(consumer.pending_count(), 3);

        let completed = consumer.consume(|batch| {
            assert_eq!(batch.len(), 3);
            batch.complete_many(0..3);
        });

        assert_eq!(completed, 3);
        driver.assert_used(&[
            (0, ExpectedUsed::Readable(6)),
            (1, ExpectedUsed::Readable(6)),
            (2, ExpectedUsed::Readable(6)),
        ]);
    }

    #[test]
    fn test_feed_respects_max_frames() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .readable(&[b"F0"])
            .readable(&[b"F1"])
            .readable(&[b"F2"])
            .readable(&[b"F3"])
            .readable(&[b"F4"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed(2);
        assert_eq!(added, 2);
        assert_eq!(consumer.pending_count(), 2);

        // Already at limit
        let added2 = consumer.feed(2);
        assert_eq!(added2, 0);
        assert_eq!(consumer.pending_count(), 2);
    }

    #[test]
    fn test_feed_transform_callback() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.readable(&[b"TestData12345"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |mut iovecs| {
            // Skip 4 bytes (like skipping vnet header)
            if !iovecs.is_empty() && iovecs[0].len() >= 4 {
                let first = &iovecs[0];
                let ptr = first.as_ptr();
                let new_len = first.len() - 4;
                let new_slice = unsafe { std::slice::from_raw_parts(ptr.add(4), new_len) };
                iovecs[0] = IoSlice::new(new_slice);
            }
            (to_iovec(iovecs), ())
        });

        assert_eq!(added, 1);

        consumer.consume(|batch| {
            batch.complete(0);
        });

        // Original guest length is 13, not 9
        driver.assert_used(&[(0, ExpectedUsed::Readable(13))]);
    }

    #[test]
    fn test_consume_and_complete_bytes() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .readable(&[b"FirstChain"])
            .readable(&[b"SecondChain"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed(10);
        assert_eq!(consumer.pending_count(), 2);

        let completed = consumer.consume(|batch| {
            assert_eq!(batch.total_bytes(), 21);
            batch.complete_many(0..batch.len());
        });

        assert_eq!(completed, 2);
        assert_eq!(consumer.pending_count(), 0);

        driver.assert_used(&[
            (0, ExpectedUsed::Readable(10)),
            (1, ExpectedUsed::Readable(11)),
        ]);
    }

    #[test]
    fn test_consume_partial() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .readable(&[b"Chain00000"])
            .readable(&[b"Chain11111"])
            .readable(&[b"Chain22222"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed(10);

        // Complete only first chain
        let completed = consumer.consume(|batch| {
            batch.complete(0);
        });

        assert_eq!(completed, 1);
        assert_eq!(consumer.pending_count(), 2);
        driver.assert_used(&[(0, ExpectedUsed::Readable(10))]);
    }

    #[test]
    fn test_compact() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed(10);
        assert_eq!(consumer.pending_count(), 5);

        // Complete 3 chains (compact is called internally)
        let completed = consumer.consume(|batch| {
            batch.complete_many(0..3);
        });
        assert_eq!(completed, 3);
        assert_eq!(consumer.pending_count(), 2);

        driver.assert_used(&[
            (0, ExpectedUsed::Readable(4)),
            (1, ExpectedUsed::Readable(4)),
            (2, ExpectedUsed::Readable(4)),
        ]);
    }

    #[test]
    fn test_empty_queue_returns_zero() {
        let mem = create_memory();
        let queue = create_test_queue();
        let _driver = VirtQueueDriver::new(&queue, &mem);
        // Don't add any descriptors

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed(10);

        assert_eq!(added, 0);
        assert_eq!(consumer.pending_count(), 0);
        // consume returns 0 when no pending chains
        let completed = consumer.consume(|_batch| {});
        assert_eq!(completed, 0);
    }

    #[test]
    fn test_no_completion_preserves_pending() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.readable(&[b"TestData"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed(10);

        // Callback doesn't complete anything (simulating EAGAIN/WouldBlock)
        let completed = consumer.consume(|_batch| {
            // Don't call complete_bytes or complete_chains
        });
        assert_eq!(completed, 0);
        assert_eq!(consumer.pending_count(), 1);

        // Nothing should be in used ring yet
        assert_eq!(driver.used_count(), 0);
    }

    #[test]
    fn test_remove_header_byte_tracking() {
        // Guest provides [header (12) | payload (100)].
        // Transform skips header. byte_count = 100 (payload only).
        // I/O returns 100 → chain complete.
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        let mut data = vec![0x48u8; 12]; // header
        data.extend(vec![0x50; 100]); // payload
        driver.readable(&[&data]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |mut iovecs| {
            // Skip 12 bytes from first iovec
            if !iovecs.is_empty() && iovecs[0].len() >= 12 {
                let first = &iovecs[0];
                let ptr = first.as_ptr();
                let new_len = first.len() - 12;
                let new_slice = unsafe { std::slice::from_raw_parts(ptr.add(12), new_len) };
                iovecs[0] = IoSlice::new(new_slice);
            }
            (to_iovec(iovecs), ())
        });
        assert_eq!(added, 1);

        let completed = consumer.consume(|batch| {
            // Sum bytes in chain 0 (should be 100, not 112)
            let total: usize = batch.io_slices(0).iter().map(|iov| iov.len()).sum();
            assert_eq!(total, 100); // payload only
            batch.complete(0);
        });

        assert_eq!(completed, 1);
        assert_eq!(consumer.pending_count(), 0);

        // add_used reports ORIGINAL guest length (112), not transformed (100)
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_multi_cycle_partial_writes() {
        // Tricky scenario: partial writes across multiple cycles.
        // Chain layout after transform: payload only (100 bytes after skipping 12-byte header)
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        let mut data = vec![0x48u8; 12]; // virtio header (skipped)
        data.extend(vec![0x50; 100]); // payload
        driver.readable(&[&data]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |mut iovecs| {
            if !iovecs.is_empty() && iovecs[0].len() >= 12 {
                let first = &iovecs[0];
                let ptr = first.as_ptr();
                let new_len = first.len() - 12;
                let new_slice = unsafe { std::slice::from_raw_parts(ptr.add(12), new_len) };
                iovecs[0] = IoSlice::new(new_slice);
            }
            (to_iovec(iovecs), ())
        });
        assert_eq!(added, 1);

        // Cycle 1: 2 bytes sent (partial)
        consumer.consume(|batch| batch.advance(0, 2));
        assert_eq!(consumer.pending_count(), 1);

        // Cycle 2: 50 more bytes (total 52)
        consumer.consume(|batch| batch.advance(0, 50));
        assert_eq!(consumer.pending_count(), 1);

        // Cycle 3: remaining 48 bytes - now complete
        consumer.consume(|batch| {
            batch.advance(0, 48);
            batch.finish(0);
        });
        assert_eq!(consumer.pending_count(), 0);

        // add_used reports ORIGINAL guest length (112)
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_stop_resume_across_compact() {
        // Feed 2 chains, partial send, compact, feed more, continue.
        // This tests that state is preserved when guest adds more descriptors mid-stream.
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        // First batch: 2 chains of 30 bytes each
        let data = vec![0x50u8; 30];
        driver.readable(&[&data]).readable(&[&data]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed(10);
        assert_eq!(consumer.pending_count(), 2);

        // Complete only first chain, advance partial on second
        consumer.consume(|batch| {
            batch.complete(0);
            batch.advance(1, 15); // partial send on chain 1 (now index 0 after compact)
        });
        assert_eq!(consumer.pending_count(), 1);

        // Compact removes completed chain 0
        // (compact is called automatically in consume, but let's verify state)

        // Guest adds more descriptors (simulating queue refill)
        driver.readable(&[&data]); // chain 2

        consumer.feed(10);
        assert_eq!(consumer.pending_count(), 2); // chain 1 (partial) + chain 2

        // Complete remaining chains
        consumer.consume(|batch| {
            batch.complete_many(0..2);
        });
        assert_eq!(consumer.pending_count(), 0);
    }
}

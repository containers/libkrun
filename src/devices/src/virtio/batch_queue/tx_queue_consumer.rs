// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TX queue consumer for batched virtio transmit operations.

use std::io::IoSlice;
use std::ops::Range;

use libc::iovec;
use vm_memory::{GuestMemory, GuestMemoryMmap};

use super::super::queue::{DescriptorChain, Queue};
use super::super::InterruptTransport;
use super::{AdvanceBytes, ChainsMemoryRepr, IovecVec};

/// Metadata for a pending descriptor chain.
#[derive(Debug, Clone)]
struct ChainMeta<M: Default> {
    head_index: u16,
    /// Total bytes in iovecs
    max_bytes: usize,
    /// Bytes from guest descriptors (for add_used reporting)
    guest_len: usize,
    /// Bytes sent so far (for partial send tracking)
    bytes_used: usize,
    finished: bool,
    /// User-defined metadata
    user_meta: M,
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
    /// Maximum number of chains to keep pending at once.
    max_chains: usize,
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
        let max_chains = queue.size as usize * 8;
        Self {
            queue,
            mem,
            interrupt,
            max_chains,
            chain_repr: Vec::new(),
            chain_meta: Vec::new(),
            sent_chains: 0,
        }
    }

    /// Set the maximum number of chains to keep pending at once.
    pub fn set_max_chains(&mut self, max: usize) {
        self.max_chains = max;
    }

    /// Feed descriptor chains from the queue, converting each into the
    /// representation type `R` via a user-supplied callback.
    ///
    /// The callback receives the chain's readable iovecs and returns an `(R, Meta)`
    /// pair. It may mutate the iovecs before building `R` — for example, skipping
    /// a header so that subsequent I/O starts after it. Any bytes consumed by
    /// the callback are automatically tracked.
    ///
    /// Returns the number of chains added.
    pub fn feed_with_transform<F>(&mut self, mut transform: F) -> usize
    where
        F: for<'a> FnMut(Vec<IoSlice<'a>>) -> (R, R::Meta),
    {
        let mut added = 0;

        if let Err(e) = self.queue.disable_notification(&self.mem) {
            warn!("Failed to disable queue notifications: {e:?}");
        }
        'next_chain: while self.pending_count() < self.max_chains {
            let Some(head) = self.queue.pop(&self.mem) else {
                // Queue exhausted: re-enable driver kicks. If more descriptors arrived in the
                // meantime, loops back to pop them; otherwise break and expect the user to wake
                // us up on the next kick.
                match self.queue.enable_notification(&self.mem) {
                    Ok(true) => continue 'next_chain,
                    Ok(false) => break 'next_chain,
                    Err(e) => {
                        error!("Failed to re-enable queue notifications: {e:?}");
                        break 'next_chain;
                    }
                }
            };

            let head_index = head.index;
            let mut iovecs: Vec<IoSlice<'_>> = Vec::new();

            for desc in head.into_iter().filter(DescriptorChain::is_read_only) {
                if let Some(iov) = unsafe { self.desc_to_ioslice(&desc) } {
                    iovecs.push(iov);
                } else {
                    log::error!("Invalid descriptor: {desc:?}, skipping the chain",);
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

            // Compute final length
            let max_bytes = repr.total_bytes();

            // Track bytes already consumed by transform
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

    /// Number of chains pending
    pub fn pending_count(&self) -> usize {
        self.chain_meta.len()
    }

    /// Check if there are any pending chains
    pub fn has_pending(&self) -> bool {
        self.pending_count() > 0
    }

    /// Consume pending chains using a callback that performs the actual I/O.
    ///
    /// The callback receives a `TxConsumerBatch` which provides:
    /// - `chain(i)` - access to chain iovecs by index (panics if already finished)
    /// - `finish(i)` / `finish_many(range)` - mark chains as finished
    ///
    /// Returns the number of chains finished. Finished chains are removed
    /// from the pending list and interrupt is signaled if needed.
    pub fn consume<F>(&mut self, f: F) -> usize
    where
        F: for<'a> FnOnce(&mut TxConsumerBatch<'a, R>),
    {
        if !self.has_pending() {
            return 0;
        }

        let finished_count;
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
            finished_count = batch.first_finished;
        }

        // Update sent_chains based on what was finished
        self.sent_chains += finished_count;

        if finished_count > 0 {
            self.signal_used_if_needed();
        }

        log::trace!(
            "consume: finished_count={} remaining={}",
            finished_count,
            self.chain_meta.len()
        );

        self.compact();
        finished_count
    }

    /// Convert a descriptor to an IoSlice pointing into guest memory.
    ///
    unsafe fn desc_to_ioslice(&self, desc: &DescriptorChain) -> Option<IoSlice<'_>> {
        let len = desc.len as usize;
        let slice = self.mem.get_slice(desc.addr, len).ok()?;
        let ptr = slice.ptr_guard_mut().as_ptr();

        // Safety: We own the GuestMemoryMmap, so the memory is valid for our lifetime.
        let byte_slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        Some(IoSlice::new(byte_slice))
    }

    /// Clears the finished chains from the begining.
    fn compact(&mut self) {
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
}

impl TxQueueConsumer<IovecVec> {
    /// Feed descriptor chains from queue without transformation.
    ///
    /// This is a convenience method for the common case where no header
    /// transformation is needed.
    pub fn feed(&mut self) -> usize {
        self.feed_with_transform(|iovecs| {
            let raw: Vec<iovec> = unsafe { std::mem::transmute(iovecs) };
            (IovecVec(raw), ())
        })
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
            "io_slices: chain at index {} already finished",
            index
        );
        let slice = &self.chain_repr[index].0[..];
        // iovec and IoSlice have the same memory layout
        unsafe { std::slice::from_raw_parts(slice.as_ptr().cast(), slice.len()) }
    }
}

/// Batch for consuming TX chains.
///
/// Provides access to pending chains and methods to mark them as finished.
///
/// Panics if you access or finish an already-finished chain.
pub struct TxConsumerBatch<'a, R: ChainsMemoryRepr> {
    chain_repr: &'a mut [R],
    chain_meta: &'a mut [ChainMeta<R::Meta>],
    queue: &'a mut Queue,
    mem: &'a GuestMemoryMmap,
    /// Index of first unfinished chain. Chains 0..first_finished are finished.
    /// For sequential finishing, this equals the number of finished chains.
    first_finished: usize,
}

impl<R: ChainsMemoryRepr> TxConsumerBatch<'_, R> {
    /// Number of pending chains in this batch.
    #[inline]
    pub fn len(&self) -> usize {
        self.chain_repr.len()
    }

    /// Check if the batch is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.chain_repr.is_empty()
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
    /// Panics if index is out of bounds or if the chain has already been finished.
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
    /// Panics if any chain in the range has already been finished.
    pub fn chains(&self, range: Range<usize>) -> &[R] {
        // Fast path: if range starts at or after first_finished, all are unfinished
        if range.start < self.first_finished {
            // Slow path: range may include finished chains, check each
            for i in range.clone() {
                self.assert_not_finished(i);
            }
        }
        &self.chain_repr[range]
    }

    /// Get total bytes across all pending (non-finished) chains.
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

        // Update first_finished for sequential finishing optimization
        if index == self.first_finished {
            while self.first_finished < self.chain_meta.len()
                && self.chain_meta[self.first_finished].finished
            {
                self.first_finished += 1;
            }
        }
    }

    /// Mark a range of chains as finished.
    ///
    /// # Panics
    ///
    /// Panics if any chain in the range has already been finished.
    pub fn finish_many(&mut self, range: Range<usize>) {
        for i in range {
            self.finish(i);
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

#[cfg(test)]
mod tests {
    use std::io::IoSlice;

    use crate::virtio::batch_queue::IovecVec;
    use crate::virtio::test_utils::{create_interrupt, ExpectedUsed, TestSetup};

    use super::TxQueueConsumer;

    /// Helper type alias for tests using default representation
    type TestTxConsumer = TxQueueConsumer;

    /// Helper to convert IoSlice to IovecVec (for test callbacks)
    fn to_iovec(iovecs: Vec<IoSlice<'_>>) -> IovecVec {
        IovecVec(unsafe { std::mem::transmute(iovecs) })
    }

    #[test]
    fn test_new_consumer_is_empty() {
        let setup = TestSetup::new();
        let (queue, _driver) = setup.create_queue(16);
        let consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        assert_eq!(consumer.pending_count(), 0);
        assert!(!consumer.has_pending());
    }

    #[test]
    fn test_feed_single_descriptor() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"Hello, World!"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed();

        assert_eq!(added, 1);
        assert_eq!(consumer.pending_count(), 1);
        assert!(consumer.has_pending());

        // Verify chain content via consume callback
        let finished = consumer.consume(|batch| {
            assert_eq!(batch.len(), 1);
            assert_eq!(batch.io_slices(0).len(), 1);
            assert_eq!(&*batch.io_slices(0)[0], b"Hello, World!");
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable(13))]);
    }

    #[test]
    fn test_feed_chained_descriptors() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        // Chain of two descriptors
        driver.readable(&[b"First", b"Second"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed();

        assert_eq!(added, 1);
        assert_eq!(consumer.pending_count(), 1);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.io_slices(0).len(), 2);
            assert_eq!(&*batch.io_slices(0)[0], b"First");
            assert_eq!(&*batch.io_slices(0)[1], b"Second");
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable(11))]);
    }

    #[test]
    fn test_feed_multiple_frames() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"Frame1"])
            .readable(&[b"Frame2"])
            .readable(&[b"Frame3"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed();

        assert_eq!(added, 3);
        assert_eq!(consumer.pending_count(), 3);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.len(), 3);
            batch.finish_many(0..3);
        });

        assert_eq!(finished, 3);
        driver.assert_used(&[
            (0, ExpectedUsed::Readable(6)),
            (1, ExpectedUsed::Readable(6)),
            (2, ExpectedUsed::Readable(6)),
        ]);
    }

    #[test]
    fn test_feed_respects_max_chains() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"F0"])
            .readable(&[b"F1"])
            .readable(&[b"F2"])
            .readable(&[b"F3"])
            .readable(&[b"F4"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());
        consumer.set_max_chains(2);

        let added = consumer.feed();
        assert_eq!(added, 2);
        assert_eq!(consumer.pending_count(), 2);

        // Already at limit
        let added2 = consumer.feed();
        assert_eq!(added2, 0);
        assert_eq!(consumer.pending_count(), 2);
    }

    #[test]
    fn test_feed_transform_callback() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"TestData12345"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed_with_transform(|mut iovecs| {
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
            batch.finish(0);
        });

        // Original guest length is 13, not 9
        driver.assert_used(&[(0, ExpectedUsed::Readable(13))]);
    }

    #[test]
    fn test_consume_and_finish_all() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"FirstChain"])
            .readable(&[b"SecondChain"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();
        assert_eq!(consumer.pending_count(), 2);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.total_bytes(), 21);
            batch.finish_many(0..batch.len());
        });

        assert_eq!(finished, 2);
        assert_eq!(consumer.pending_count(), 0);

        driver.assert_used(&[
            (0, ExpectedUsed::Readable(10)),
            (1, ExpectedUsed::Readable(11)),
        ]);
    }

    #[test]
    fn test_consume_partial() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"Chain00000"])
            .readable(&[b"Chain11111"])
            .readable(&[b"Chain22222"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();

        // Finish only first chain
        let finished = consumer.consume(|batch| {
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        assert_eq!(consumer.pending_count(), 2);
        driver.assert_used(&[(0, ExpectedUsed::Readable(10))]);
    }

    #[test]
    fn test_compact() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();
        assert_eq!(consumer.pending_count(), 5);

        // Finish 3 chains (compact is called internally)
        let finished = consumer.consume(|batch| {
            batch.finish_many(0..3);
        });
        assert_eq!(finished, 3);
        assert_eq!(consumer.pending_count(), 2);

        driver.assert_used(&[
            (0, ExpectedUsed::Readable(4)),
            (1, ExpectedUsed::Readable(4)),
            (2, ExpectedUsed::Readable(4)),
        ]);
    }

    #[test]
    fn test_empty_queue_returns_zero() {
        let setup = TestSetup::new();
        let (queue, _driver) = setup.create_queue(16);
        // Don't add any descriptors

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed();

        assert_eq!(added, 0);
        assert_eq!(consumer.pending_count(), 0);
        // consume returns 0 when no pending chains
        let finished = consumer.consume(|_batch| {});
        assert_eq!(finished, 0);
    }

    #[test]
    fn test_no_finish_preserves_pending() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"TestData"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();

        // Callback doesn't finish anything (simulating EAGAIN/WouldBlock)
        let finished = consumer.consume(|_batch| {});
        assert_eq!(finished, 0);
        assert_eq!(consumer.pending_count(), 1);

        // Nothing should be in used ring yet
        assert_eq!(driver.used_count(), 0);
    }

    #[test]
    fn test_remove_header_byte_tracking() {
        // Guest provides [header (12) | payload (100)].
        // Transform skips header. byte_count = 100 (payload only).
        // I/O returns 100 → chain finished.
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);

        let mut data = vec![0x48u8; 12]; // header
        data.extend(vec![0x50; 100]); // payload
        driver.readable(&[&data]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed_with_transform(|mut iovecs| {
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

        let finished = consumer.consume(|batch| {
            // Sum bytes in chain 0 (should be 100, not 112)
            let total: usize = batch.io_slices(0).iter().map(|iov| iov.len()).sum();
            assert_eq!(total, 100); // payload only
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        assert_eq!(consumer.pending_count(), 0);

        // add_used reports ORIGINAL guest length (112), not transformed (100)
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_multi_cycle_partial_writes() {
        // Tricky scenario: partial writes across multiple cycles.
        // Chain layout after transform: payload only (100 bytes after skipping 12-byte header)
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);

        let mut data = vec![0x48u8; 12]; // virtio header (skipped)
        data.extend(vec![0x50; 100]); // payload
        driver.readable(&[&data]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed_with_transform(|mut iovecs| {
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

        // Cycle 3: remaining 48 bytes - now finished
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
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);

        // First batch: 2 chains of 30 bytes each
        let data = vec![0x50u8; 30];
        driver.readable(&[&data]).readable(&[&data]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();
        assert_eq!(consumer.pending_count(), 2);

        // Finish only first chain, advance partial on second
        consumer.consume(|batch| {
            batch.finish(0);
            batch.advance(1, 15);
        });
        assert_eq!(consumer.pending_count(), 1);

        // Only chain 0 in used ring so far
        driver.assert_used(&[(0, ExpectedUsed::Readable(30))]);

        // Guest adds more descriptors (simulating queue refill)
        driver.readable(&[&data]); // chain 2

        consumer.feed();
        assert_eq!(consumer.pending_count(), 2); // chain 1 (partial) + chain 2

        // Finish remaining chains
        consumer.consume(|batch| {
            batch.finish_many(0..2);
        });
        assert_eq!(consumer.pending_count(), 0);

        // All 3 chains, including the one that crossed a compact boundary
        driver.assert_used(&[
            (0, ExpectedUsed::Readable(30)),
            (1, ExpectedUsed::Readable(30)),
            (2, ExpectedUsed::Readable(30)),
        ]);
    }

    #[test]
    fn test_out_of_order_finish() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"pkt0"])
            .readable(&[b"pkt1"])
            .readable(&[b"pkt2"])
            .readable(&[b"pkt3"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();
        assert_eq!(consumer.pending_count(), 4);

        // Finish chains 3 and 1 (out of order), leave 0 and 2 pending
        let finished = consumer.consume(|batch| {
            batch.finish(3);
            batch.finish(1);
        });

        // first_finished never advanced past 0 (chain 0 not finished),
        // so compact doesn't remove anything yet
        assert_eq!(finished, 0);
        assert_eq!(consumer.pending_count(), 4);

        // Used ring has both entries in finish-call order
        driver.assert_used(&[
            (3, ExpectedUsed::ReadableAnyLen),
            (1, ExpectedUsed::ReadableAnyLen),
        ]);

        // Finish chain 0 — first_finished jumps 0→2 (skipping already-finished 1)
        let finished = consumer.consume(|batch| {
            batch.finish(0);
        });

        assert_eq!(finished, 2); // compact removes 0 and 1
        assert_eq!(consumer.pending_count(), 2); // chains 2 and 3 remain

        // Finish remaining: chain 2 (index 0) then chain 3 (index 1, already finished)
        // Chain 3 was finished in the first cycle but not compacted until now
        let finished = consumer.consume(|batch| {
            batch.finish(0); // chain 2
        });

        // first_finished: 0→1, then chain 1 (original 3) already finished → jumps to 2
        assert_eq!(finished, 2);
        assert_eq!(consumer.pending_count(), 0);

        // All 4 in used ring in the order finish() was called
        driver.assert_used(&[
            (3, ExpectedUsed::ReadableAnyLen),
            (1, ExpectedUsed::ReadableAnyLen),
            (0, ExpectedUsed::ReadableAnyLen),
            (2, ExpectedUsed::ReadableAnyLen),
        ]);
    }

    #[test]
    #[should_panic(expected = "already finished")]
    fn test_double_finish_panics() {
        let setup = TestSetup::new();
        let (queue, _driver) = setup.create_queue(16);
        _driver.readable(&[b"data"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();
        consumer.consume(|batch| {
            batch.finish(0);
            batch.finish(0); // panic: already finished
        });
    }
}

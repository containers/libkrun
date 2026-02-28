// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RX queue producer for batched virtio receive operations.

use std::io::IoSliceMut;
use std::ops::Range;

use libc::iovec;
use vm_memory::{GuestMemory, GuestMemoryMmap};

use super::super::queue::{DescriptorChain, Queue};
use super::super::InterruptTransport;
use super::iovec_utils::write_to_iovecs;
use super::{AdvanceBytes, ChainsMemoryRepr, IovecVec, ReceivedLen, TruncateBytes};

/// Metadata for a pending descriptor chain.
#[derive(Debug)]
struct ChainMeta<M: Default> {
    head_index: u16,
    max_bytes: usize,
    bytes_used: usize,
    finished: bool,
    /// User-defined metadata
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
    /// Maximum number of chains to keep pending at once.
    max_chains: usize,
    /// Per-chain representation (type depends on R)
    chain_repr: Vec<R>,
    /// Metadata for each chain (parallel to chain_repr)
    chain_meta: Vec<ChainMeta<R::Meta>>,
}

impl<R: ChainsMemoryRepr> RxQueueProducer<R> {
    /// Create a new RxQueueProducer with the given queue, memory, and interrupt.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> Self {
        let max_chains = queue.size as usize * 8;
        Self {
            queue,
            mem,
            interrupt,
            max_chains,
            chain_repr: Vec::new(),
            chain_meta: Vec::new(),
        }
    }

    /// Set the maximum number of chains to keep pending at once.
    pub fn set_max_chains(&mut self, max: usize) {
        self.max_chains = max;
    }

    /// Feed descriptor chains from the queue, converting each into the
    /// representation type `R` via a user-supplied callback.
    ///
    /// The callback receives the chain's writable iovecs and returns an `(R, Meta)`
    /// pair. It may mutate the iovecs before building `R` — for example, writing
    /// a header and advancing past it so that subsequent I/O starts after the
    /// header. Any bytes consumed by the callback are automatically tracked.
    ///
    /// Returns the number of chains added.
    ///
    pub fn feed_with_transform<F>(&mut self, mut transform: F) -> usize
    where
        F: for<'a> FnMut(Vec<IoSliceMut<'a>>) -> (R, R::Meta),
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
            let mut iovecs: Vec<IoSliceMut<'_>> = Vec::new();

            for desc in head.into_iter().filter(DescriptorChain::is_write_only) {
                if let Some(iov) = unsafe { self.desc_to_ioslice_mut(&desc) } {
                    iovecs.push(iov);
                } else {
                    log::error!("Invalid descriptor: {desc:?}, skipping the chain",);
                    continue 'next_chain;
                }
            }

            if iovecs.is_empty() {
                log::warn!("Found empty chain, ignoring it");
                continue 'next_chain;
            }

            // Compute original chain length before transformation
            let max_bytes: usize = iovecs.iter().map(|iov| iov.len()).sum();

            // Apply transformation (callback takes ownership, returns representation)
            let (repr, user_meta) = transform(iovecs);

            // Track bytes already consumed by transform
            let bytes_used = max_bytes - repr.total_bytes();

            self.chain_repr.push(repr);
            self.chain_meta.push(ChainMeta {
                head_index,
                max_bytes,
                bytes_used,
                finished: false,
                user_meta,
            });
            added += 1;
        }

        added
    }

    /// Number of chains pending (not yet sent)
    pub fn pending_count(&self) -> usize {
        self.chain_meta.len()
    }

    /// Check if there are any pending chains
    pub fn has_pending(&self) -> bool {
        self.pending_count() > 0
    }

    /// Convert a descriptor to a mutable IoSlice pointing into guest memory.
    ///
    /// Returns None if the descriptor's memory region cannot be found or mapped.
    ///
    unsafe fn desc_to_ioslice_mut(&self, desc: &DescriptorChain) -> Option<IoSliceMut<'_>> {
        let len = desc.len as usize;
        let slice = self.mem.get_slice(desc.addr, len).ok()?;
        let ptr = slice.ptr_guard_mut().as_ptr();

        // Safety: We own the GuestMemoryMmap, so the memory is valid for our lifetime.
        // The slice points into pinned guest memory that won't move.
        let byte_slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };

        // Transmute to 'static - safe because we own the memory reference
        let static_slice: &mut [u8] = unsafe { std::mem::transmute(byte_slice) };

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
            log::info!("produce: no chains pending, returning 0");
            return 0;
        }

        log::info!(
            "produce: {} chains pending, calling callback",
            self.chain_meta.len()
        );

        let mut batch = RxProducerBatch {
            chain_repr: &mut self.chain_repr,
            chain_meta: &mut self.chain_meta,
            queue: &mut self.queue,
            mem: &self.mem,
            first_unfinished: 0,
        };

        f(&mut batch);
        let finished_count = self.compact();

        if finished_count > 0 {
            self.signal_used_if_needed();
        }

        log::trace!(
            "produce: finished_count={} remaining={}",
            finished_count,
            self.chain_meta.len()
        );

        finished_count
    }

    // Remove finished chains in O(n) by swapping unfinished to front, then truncating
    // (for producer we don't care about the order of the descriptor chains)
    fn compact(&mut self) -> usize {
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
}

/// Convenience methods for the default representation type (IovecVec).
impl RxQueueProducer<IovecVec> {
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
    /// Number of chains in the batch.
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

    /// Get bytes already produced for chain at index.
    #[inline]
    pub fn bytes_used(&self, index: usize) -> usize {
        self.chain_meta[index].bytes_used
    }

    /// Get maximum bytes the chain can hold.
    #[inline]
    pub fn max_bytes(&self, index: usize) -> usize {
        self.chain_meta[index].max_bytes
    }

    /// Get reference to the user-defined metadata for chain at index.
    #[inline]
    pub fn user_meta(&self, index: usize) -> &R::Meta {
        &self.chain_meta[index].user_meta
    }

    // Get mutable access to the chain at index.
    ///
    /// # Panics
    ///
    /// Panics if index is out of bounds or if the chain has already been finished.
    pub fn chain_mut(&mut self, index: usize) -> &mut R {
        self.assert_not_finished(index);
        &mut self.chain_repr[index]
    }

    /// Get mutable access to chains in a range (checked).
    ///
    /// O(1) if chains are being finished sequentially, O(n) otherwise.
    ///
    /// # Panics
    ///
    /// Panics if any chain in the range has already been finished.
    pub fn chains_mut(&mut self, range: Range<usize>) -> &mut [R] {
        self.assert_range_not_finished(range.clone());
        &mut self.chain_repr[range]
    }

    /// Finish a range of chains, reporting them to the guest.
    ///
    /// The received byte count should already have been set via
    /// [`advance`](Self::advance). To set the byte count and finish in one
    /// step, use [`complete`](Self::complete) or [`complete_many`](Self::complete_many).
    ///
    /// Chains can be finished out-of-order, but sequential finishing
    /// (0, 1, 2...) is preferable.
    ///
    /// O(1) if chains are being finished sequentially, O(n) otherwise.
    ///
    /// # Panics
    ///
    /// Panics if any chain in the range has already been finished.
    pub fn finish_many(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }

        let range_start = range.start;
        let range_end = range.end;

        for i in range {
            self.assert_not_finished(i);
            let meta = &mut self.chain_meta[i];
            meta.finished = true;

            log::trace!(
                "finishing chain index={} head_index={} bytes_used={}",
                i,
                meta.head_index,
                meta.bytes_used
            );

            if let Err(e) = self
                .queue
                .add_used(self.mem, meta.head_index, meta.bytes_used as u32)
            {
                log::error!("failed to add_used: {e}");
            }
        }

        debug_assert!(range_start >= self.first_unfinished);
        if range_start == self.first_unfinished {
            // Jump to the end of the range we just verified and finished
            self.first_unfinished = range_end;

            // Scan forward in case there were out-of-order finishes sitting ahead of us
            while self.first_unfinished < self.chain_meta.len()
                && self.chain_meta[self.first_unfinished].finished
            {
                self.first_unfinished += 1;
            }
        }
    }

    /// Finish a chain, reporting it to the guest.
    ///
    /// The received byte count should already have been set via
    /// [`advance`](Self::advance). To set the byte count and finish in one
    /// step, use [`complete`](Self::complete).
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn finish(&mut self, index: usize) {
        self.finish_many(index..index + 1);
    }

    #[track_caller]
    #[inline]
    fn assert_range_not_finished(&self, range: Range<usize>) {
        // Fast path: if range starts at or after first_unfinished, all are unfinished
        if range.start < self.first_unfinished {
            // Slow path: range may include finished chains, check each
            for i in range {
                self.assert_not_finished(i);
            }
        }
    }

    /// Set the received byte count and finish the chain, reporting it to the guest.
    ///
    /// This is the primary way to hand a received buffer back to the guest.
    /// If the byte count was already set via [`advance`](Self::advance), use
    /// [`finish`](Self::finish) instead.
    ///
    /// See also [`complete_received`](Self::complete_received) when the chain
    /// representation knows its own received length.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn complete(&mut self, index: usize, bytes: usize) {
        let meta = &mut self.chain_meta[index];
        meta.bytes_used += bytes;
        debug_assert!(
            meta.bytes_used <= meta.max_bytes,
            "complete: bytes_used {} exceeds max_bytes {}",
            meta.bytes_used,
            meta.max_bytes
        );
        self.finish(index);
    }

    #[track_caller]
    #[inline]
    fn assert_not_finished(&self, index: usize) {
        assert!(
            !self.is_finished(index),
            "chain at index {index} already finished",
        );
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

/// Methods for representation types that report their own received byte count.
impl<R: ChainsMemoryRepr + ReceivedLen> RxProducerBatch<'_, R> {
    /// Complete a chain, reading the received byte count from the chain's
    /// [`ReceivedLen`] implementation and reporting it to the guest.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn complete_received(&mut self, index: usize) {
        self.complete_received_many(index..index + 1);
    }

    /// Complete a range of chains, reading the received byte count from each
    /// chain's [`ReceivedLen`] implementation and reporting them to the guest.
    ///
    ///
    /// # Panics
    ///
    /// Panics if any chain in the range has already been finished.
    pub fn complete_received_many(&mut self, range: Range<usize>) {
        for i in range.clone() {
            self.chain_meta[i].bytes_used += self.chain_repr[i].received_len();
        }
        self.finish_many(range);
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

#[cfg(test)]
mod tests {
    use std::io::IoSliceMut;

    use std::cell::Cell;

    use libc::iovec;

    use crate::virtio::batch_queue::iovec_utils::{advance_iovecs_vec, write_to_iovecs};
    use crate::virtio::batch_queue::{ChainsMemoryRepr, IovecVec, ReceivedLen};
    use crate::virtio::test_utils::{create_interrupt, ExpectedUsed, TestSetup};

    use super::RxQueueProducer;

    /// Helper type alias for tests using default representation
    type TestRxProducer = RxQueueProducer;

    /// Helper to convert IoSliceMut to IovecVec (for test callbacks)
    fn to_iovec(iovecs: Vec<IoSliceMut<'_>>) -> IovecVec {
        IovecVec(unsafe { std::mem::transmute(iovecs) })
    }

    #[test]
    fn test_initial_state() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        assert_eq!(producer.pending_count(), 0);
        assert_eq!(producer.feed(), 0);
        assert_eq!(producer.pending_count(), 0);
        assert_eq!(producer.produce(|_batch| {}), 0);
        driver.assert_used(&[]);
    }

    #[test]
    fn test_feed_single_writable_descriptor() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        let added = producer.feed();

        assert_eq!(added, 1);
        assert_eq!(producer.pending_count(), 1);
    }

    #[test]
    fn test_feed_chained_writable_descriptors() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        // Chain of 2 writable descriptors
        driver.writable(&[512, 1024]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        let added = producer.feed();

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

        // We haven't finished anything
        driver.assert_used(&[]);
    }

    #[test]
    fn test_feed_respects_max_frames() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());
        producer.set_max_chains(2);

        let added = producer.feed();

        assert_eq!(added, 2);
        assert_eq!(producer.pending_count(), 2);
    }

    #[test]
    fn test_produce_via_write_bytes() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.writable(&[10, 90]).writable(&[100]).writable(&[100]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        producer.feed();
        assert_eq!(producer.pending_count(), 3);

        let completed = producer.produce(|batch| {
            assert_eq!(batch.max_bytes(0), 100);
            batch.write_complete(0, b"Received packet 1").unwrap();
            assert_eq!(batch.bytes_used(0), 17);
            assert!(batch.is_finished(0));

            assert_eq!(batch.max_bytes(1), 100);
            batch.write_complete(1, b"Received packet 2").unwrap();
            assert_eq!(batch.bytes_used(1), 17);
            assert!(batch.is_finished(1));

            // Third left unfinished
            assert_eq!(batch.max_bytes(2), 100);
            assert_eq!(batch.bytes_used(2), 0);
            assert!(!batch.is_finished(2));
        });

        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 1);

        // Verify add_used was called with actual bytes written (17), not buffer capacity (1500)
        // Also verifies the content written to guest memory
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"Received packet 1")),
            (1, ExpectedUsed::Writable(b"Received packet 2")),
        ]);
    }

    #[test]
    fn test_multiple_produce_cycles() {
        // Each chain: 3 descriptors [6, 12, 6] = 24 bytes raw.
        // Transform writes "HD" (2 bytes) header then advances past it.
        // Usable iovecs after transform: [4, 12, 6] = 22 bytes.
        //
        // Leftover state per cycle:
        //   cycle 1 → 2 leftover  (1 partial, 1 untouched)
        //   cycle 2 → 3 leftover  (complete the partial, 3 untouched)
        //   cycle 3 → 1 leftover  (complete 2 of 3)
        //   cycle 4 → 0 leftover  (drain everything)
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(32);

        driver
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        let feed_with_hdr = |p: &mut TestRxProducer| {
            p.feed_with_transform(|mut iovecs| {
                write_to_iovecs(&mut iovecs, b"HD");
                advance_iovecs_vec(&mut iovecs, 2);
                (to_iovec(iovecs), ())
            })
        };

        // ── Cycle 1: feed 3, complete 1, partial 1, leave 1 untouched ───
        assert_eq!(feed_with_hdr(&mut producer), 3);
        assert_eq!(producer.pending_count(), 3);

        let completed = producer.produce(|batch| {
            // Chain 0: 18-byte write spanning all 3 iovecs, complete
            batch.write_complete(0, b"aaaaaaaaaaaaaaaaaa").unwrap();

            // Chain 1: partial write (4 bytes into first iovec)
            let written = write_to_iovecs(batch.io_slices_mut(1), b"bbbb");
            assert_eq!(written, 4);
            batch.advance(1, 4);

            // Chain 2: untouched
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 2);

        driver.assert_used(&[(0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa"))]);

        // ── Cycle 2: guest adds 2 buffers, complete the partial ─────────
        driver
            .writable(&[1, 1, 3, 3, 12, 6]) // 6 descriptors, HD consumes first two → [3, 3, 12, 6] usable
            .writable(&[6, 12, 6]);
        assert_eq!(feed_with_hdr(&mut producer), 2);
        assert_eq!(producer.pending_count(), 4);

        let completed = producer.produce(|batch| {
            // Batch[0] (chain 1): continue partial, write 8 more b's
            let written = write_to_iovecs(batch.io_slices_mut(0), b"bbbbbbbb");
            assert_eq!(written, 8);
            batch.complete(0, 8);

            // Batch[1..3]: untouched (simulating no more packets this cycle)
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 3);

        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa")),
            (1, ExpectedUsed::Writable(b"HDbbbbbbbbbbbb")),
        ]);

        // ── Cycle 3: no new buffers, complete 2 of 3, leave 1 ──────────
        let completed = producer.produce(|batch| {
            assert_eq!(batch.len(), 3);
            batch.write_complete(0, b"cccccccccccc").unwrap();
            batch.write_complete(1, b"dddddd").unwrap(); // spans [3, 3] boundary
                                                         // Batch[2]: untouched
        });
        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 1);

        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa")),
            (1, ExpectedUsed::Writable(b"HDbbbbbbbbbbbb")),
            (2, ExpectedUsed::Writable(b"HDcccccccccccc")),
            (3, ExpectedUsed::Writable(b"HDdddddd")),
        ]);

        // ── Cycle 4: guest adds 1 buffer, complete both remaining ───────
        driver.writable(&[6, 12, 6]);
        assert_eq!(feed_with_hdr(&mut producer), 1);
        assert_eq!(producer.pending_count(), 2);

        let completed = producer.produce(|batch| {
            assert_eq!(batch.len(), 2);
            batch.write_complete(0, b"eeee").unwrap();
            batch.write_complete(1, b"ffff").unwrap();
        });
        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 0);

        // Letter = chain index: a=0, b=1, c=2, d=3, e=4, f=5
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa")),
            (1, ExpectedUsed::Writable(b"HDbbbbbbbbbbbb")),
            (2, ExpectedUsed::Writable(b"HDcccccccccccc")),
            (3, ExpectedUsed::Writable(b"HDdddddd")),
            (4, ExpectedUsed::Writable(b"HDeeee")),
            (5, ExpectedUsed::Writable(b"HDffff")),
        ]);
    }

    #[test]
    fn test_out_of_order_completion() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .writable(&[2, 2])
            .writable(&[2, 2])
            .writable(&[2, 2])
            .writable(&[2, 2]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        producer.feed();
        assert_eq!(producer.pending_count(), 4);

        // Complete chains 3 and 1 (out of order), leave 0 and 2 pending
        let completed = producer.produce(|batch| {
            batch.write_complete(3, b"pkt3").unwrap();
            batch.write_complete(1, b"pkt1").unwrap();
        });

        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 2);

        // Used ring reflects completion order (3 then 1)
        driver.assert_used(&[
            (3, ExpectedUsed::Writable(b"pkt3")),
            (1, ExpectedUsed::Writable(b"pkt1")),
        ]);

        // Complete remaining chains, also out of order
        let completed = producer.produce(|batch| {
            batch.write_complete(1, b"pkt2").unwrap();
            batch.write_complete(0, b"pkt0").unwrap();
        });

        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 0);

        // All 4 chains in used ring in the order they were completed
        driver.assert_used(&[
            (3, ExpectedUsed::Writable(b"pkt3")),
            (1, ExpectedUsed::Writable(b"pkt1")),
            (2, ExpectedUsed::Writable(b"pkt2")),
            (0, ExpectedUsed::Writable(b"pkt0")),
        ]);
    }

    /// Custom representation simulating recvmmsg-style batch receive.
    /// Each chain stores iovecs + a filled received_len (like mmsghdr.msg_len).
    struct CustomChainRepr {
        iovecs: Vec<iovec>,
        received_len: Cell<usize>,
    }

    impl CustomChainRepr {
        /// Writes `data` across the iovec scatter list and sets received_len.
        fn simulate_recv(&mut self, data: &[u8]) {
            // Safety: IoSliceMut is #[repr(transparent)] over iovec.
            let slices: &mut [IoSliceMut] = unsafe {
                std::slice::from_raw_parts_mut(
                    self.iovecs.as_mut_ptr() as *mut IoSliceMut,
                    self.iovecs.len(),
                )
            };
            let written = write_to_iovecs(slices, data);
            self.received_len.set(written);
        }
    }

    unsafe impl ChainsMemoryRepr for CustomChainRepr {
        type Meta = u32; // tag to verify metadata works

        fn len(&self) -> usize {
            self.iovecs.len()
        }

        fn total_bytes(&self) -> usize {
            self.iovecs.iter().map(|iov| iov.iov_len).sum()
        }

        fn clear(&mut self, _meta: &mut u32) {
            self.iovecs.clear();
            self.received_len.set(0);
        }
    }

    impl ReceivedLen for CustomChainRepr {
        fn received_len(&self) -> usize {
            self.received_len.get()
        }
    }

    unsafe impl Send for CustomChainRepr {}

    #[test]
    fn test_complete_received_many() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .writable(&[100])
            .writable(&[100])
            .writable(&[100])
            .writable(&[100]);

        let mut producer: RxQueueProducer<CustomChainRepr> =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        // Feed with meta tags 10, 20, 30, 40
        let mut tag = 0u32;
        let added = producer.feed_with_transform(|iovecs| {
            tag += 10;
            let raw: Vec<iovec> = unsafe { std::mem::transmute(iovecs) };
            let repr = CustomChainRepr {
                iovecs: raw,
                received_len: Cell::new(0),
            };
            (repr, tag)
        });
        assert_eq!(added, 4);

        // Simulate recvmmsg: kernel writes data + fills received_len on each repr.
        let completed = producer.produce(|batch| {
            assert_eq!(batch.len(), 4);

            // Verify meta tags round-tripped
            assert_eq!(*batch.user_meta(0), 10);
            assert_eq!(*batch.user_meta(1), 20);
            assert_eq!(*batch.user_meta(2), 30);
            assert_eq!(*batch.user_meta(3), 40);

            // Simulate kernel writing data (like recvmmsg would)
            batch.chain_mut(0).simulate_recv(b"aaaa");
            batch.chain_mut(1).simulate_recv(b"bbbbbbbb");
            // chain 2: no data yet, leave pending
            batch.chain_mut(3).simulate_recv(b"dddddddddddd");

            // Batch complete first two chains
            batch.complete_received_many(0..2);
            assert!(batch.is_finished(0));
            assert!(batch.is_finished(1));
            assert_eq!(batch.bytes_used(0), 4);
            assert_eq!(batch.bytes_used(1), 8);

            // Single complete for chain 3
            batch.complete_received(3);
            assert!(batch.is_finished(3));
            assert_eq!(batch.bytes_used(3), 12);

            // Chain 2 left pending
            assert!(!batch.is_finished(2));
        });
        assert_eq!(completed, 3);
        assert_eq!(producer.pending_count(), 1);

        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"aaaa")),
            (1, ExpectedUsed::Writable(b"bbbbbbbb")),
            (3, ExpectedUsed::Writable(b"dddddddddddd")),
        ]);

        // ── Cycle 2: complete the remaining chain ─────────────────────────
        let completed = producer.produce(|batch| {
            assert_eq!(batch.len(), 1);
            // Verify meta survived compaction (chain 2 had tag 30)
            assert_eq!(*batch.user_meta(0), 30);

            batch.chain_mut(0).simulate_recv(b"cccccc");
            batch.complete_received(0);
            assert_eq!(batch.bytes_used(0), 6);
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 0);

        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"aaaa")),
            (1, ExpectedUsed::Writable(b"bbbbbbbb")),
            (3, ExpectedUsed::Writable(b"dddddddddddd")),
            (2, ExpectedUsed::Writable(b"cccccc")),
        ]);
    }

    #[test]
    #[should_panic(expected = "already finished")]
    fn test_double_finish_panics() {
        let setup = TestSetup::new();
        let (queue, _driver) = setup.create_queue(16);
        _driver.writable(&[100]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        producer.feed();
        producer.produce(|batch| {
            batch.complete(0, 10);
            batch.complete(0, 10); // panic: already finished
        });
    }
}

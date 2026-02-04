// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for TxQueueConsumer and RxQueueProvider.

#[cfg(test)]
mod tests {
    use std::io::IoSlice;

    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::{VirtQueue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::virtio::rx_queue_producer::RxQueueProducer;
    use crate::virtio::tx_queue_consumer::TxQueueConsumer;
    use crate::virtio::InterruptTransport;

    // Memory layout constants
    const QUEUE_ADDR: u64 = 0;
    const DATA_ADDR: u64 = 0x2000;
    const MEM_SIZE: u64 = 0x10000;
    const QUEUE_SIZE: u16 = 16;

    /// Create a GuestMemoryMmap for testing
    fn create_memory() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE as usize)]).unwrap()
    }

    /// Create an InterruptTransport for testing
    fn create_interrupt() -> InterruptTransport {
        InterruptTransport::new(DummyIrqChip::new().into(), "test".to_string()).unwrap()
    }

    /// Helper to read data from guest memory
    fn read_data(mem: &GuestMemoryMmap, addr: GuestAddress, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        mem.read(&mut buf, addr).unwrap();
        buf
    }

    // ============================================================================
    // VirtQueue Setup Helpers
    // ============================================================================

    use std::cell::Cell;

    /// Stateful test harness for VirtQueue that persists across multiple add cycles.
    /// Simulates a guest driver that adds descriptors, waits for device to consume,
    /// then adds more descriptors.
    #[allow(dead_code)]
    struct VirtQueueHarness<'a> {
        vq: VirtQueue<'a>,
        mem: &'a GuestMemoryMmap,
        /// Next descriptor table index to use
        desc_idx: Cell<usize>,
        /// Next available ring index (matches vq.avail.idx)
        avail_idx: Cell<usize>,
        /// Next memory address for data allocation
        next_addr: Cell<u64>,
    }

    #[allow(dead_code)]
    impl<'a> VirtQueueHarness<'a> {
        fn new(mem: &'a GuestMemoryMmap) -> Self {
            let vq = VirtQueue::new(GuestAddress(QUEUE_ADDR), mem, QUEUE_SIZE);
            Self {
                vq,
                mem,
                desc_idx: Cell::new(0),
                avail_idx: Cell::new(0),
                next_addr: Cell::new(DATA_ADDR),
            }
        }

        /// Create the Queue for the consumer/provider.
        fn create_queue(&self) -> crate::virtio::Queue {
            self.vq.create_queue()
        }

        /// Add a readable frame (single descriptor chain) with given data.
        fn add_readable(&self, data: &[u8]) {
            let addr = self.next_addr.get();
            let size = data.len() as u64;
            self.next_addr.set(addr + std::cmp::max(size, 0x100));
            assert!(self.next_addr.get() <= MEM_SIZE, "out of memory");

            self.mem.write(data, GuestAddress(addr)).unwrap();

            let idx = self.desc_idx.get();
            assert!(idx < QUEUE_SIZE as usize, "descriptor table full");
            self.vq.dtable[idx].set(addr, data.len() as u32, 0, 0);
            self.desc_idx.set(idx + 1);

            let avail = self.avail_idx.get();
            self.vq.avail.ring[avail].set(idx as u16);
            self.avail_idx.set(avail + 1);
            self.vq.avail.idx.set(self.avail_idx.get() as u16);
        }

        /// Add a writable buffer (single descriptor chain) with given size.
        fn add_writable(&self, len: u32) {
            let addr = self.next_addr.get();
            self.next_addr.set(addr + std::cmp::max(len as u64, 0x100));
            assert!(self.next_addr.get() <= MEM_SIZE, "out of memory");

            let idx = self.desc_idx.get();
            assert!(idx < QUEUE_SIZE as usize, "descriptor table full");
            self.vq.dtable[idx].set(addr, len, VIRTQ_DESC_F_WRITE, 0);
            self.desc_idx.set(idx + 1);

            let avail = self.avail_idx.get();
            self.vq.avail.ring[avail].set(idx as u16);
            self.avail_idx.set(avail + 1);
            self.vq.avail.idx.set(self.avail_idx.get() as u16);
        }

        /// Add a chained readable frame (multiple descriptors forming one chain).
        fn add_readable_chained(&self, segments: &[&[u8]]) {
            assert!(!segments.is_empty());
            let head_idx = self.desc_idx.get();

            for (i, data) in segments.iter().enumerate() {
                let addr = self.next_addr.get();
                let size = data.len() as u64;
                self.next_addr.set(addr + std::cmp::max(size, 0x100));
                assert!(self.next_addr.get() <= MEM_SIZE, "out of memory");

                self.mem.write(data, GuestAddress(addr)).unwrap();

                let idx = self.desc_idx.get();
                assert!(idx < QUEUE_SIZE as usize, "descriptor table full");

                let is_last = i == segments.len() - 1;
                let flags = if is_last { 0 } else { VIRTQ_DESC_F_NEXT };
                let next = if is_last { 0 } else { (idx + 1) as u16 };

                self.vq.dtable[idx].set(addr, data.len() as u32, flags, next);
                self.desc_idx.set(idx + 1);
            }

            let avail = self.avail_idx.get();
            self.vq.avail.ring[avail].set(head_idx as u16);
            self.avail_idx.set(avail + 1);
            self.vq.avail.idx.set(self.avail_idx.get() as u16);
        }

        /// Add a chained writable buffer (multiple descriptors forming one chain).
        fn add_writable_chained(&self, sizes: &[u32]) {
            assert!(!sizes.is_empty());
            let head_idx = self.desc_idx.get();

            for (i, &len) in sizes.iter().enumerate() {
                let addr = self.next_addr.get();
                self.next_addr.set(addr + std::cmp::max(len as u64, 0x100));
                assert!(self.next_addr.get() <= MEM_SIZE, "out of memory");

                let idx = self.desc_idx.get();
                assert!(idx < QUEUE_SIZE as usize, "descriptor table full");

                let is_last = i == sizes.len() - 1;
                let flags = VIRTQ_DESC_F_WRITE | if is_last { 0 } else { VIRTQ_DESC_F_NEXT };
                let next = if is_last { 0 } else { (idx + 1) as u16 };

                self.vq.dtable[idx].set(addr, len, flags, next);
                self.desc_idx.set(idx + 1);
            }

            let avail = self.avail_idx.get();
            self.vq.avail.ring[avail].set(head_idx as u16);
            self.avail_idx.set(avail + 1);
            self.vq.avail.idx.set(self.avail_idx.get() as u16);
        }
    }

    /// Helper for building descriptor chains in tests (legacy, still used by some tests).
    struct DescChainBuilder<'a, 'b> {
        vq: &'a VirtQueue<'b>,
        mem: &'a GuestMemoryMmap,
        desc_idx: usize,
        avail_idx: usize,
        chain_head: Option<u16>,
        prev_desc: Option<u16>,
        next_addr: u64,
    }

    impl<'a, 'b> DescChainBuilder<'a, 'b> {
        fn new(vq: &'a VirtQueue<'b>, mem: &'a GuestMemoryMmap) -> Self {
            Self {
                vq,
                mem,
                desc_idx: 0,
                avail_idx: 0,
                chain_head: None,
                prev_desc: None,
                next_addr: DATA_ADDR,
            }
        }

        /// Add a readable descriptor with data (for TX).
        fn readable(mut self, data: &[u8]) -> Self {
            let addr = self.next_addr;
            let size = data.len() as u64;
            self.next_addr += std::cmp::max(size, 0x100);
            assert!(self.next_addr <= MEM_SIZE, "descriptor data exceeds guest memory");

            self.mem.write(data, GuestAddress(addr)).unwrap();
            self.add_desc(addr, data.len() as u32, 0);
            self
        }

        /// Add a writable descriptor buffer (for RX).
        fn writable(mut self, len: u32) -> Self {
            let addr = self.next_addr;
            self.next_addr += std::cmp::max(len as u64, 0x100);
            assert!(self.next_addr <= MEM_SIZE, "descriptor buffer exceeds guest memory");

            self.add_desc(addr, len, VIRTQ_DESC_F_WRITE);
            self
        }

        /// End the current chain and make it available.
        fn end_chain(mut self) -> Self {
            if let Some(head) = self.chain_head.take() {
                assert!(self.avail_idx < QUEUE_SIZE as usize, "available ring overflow");
                self.vq.avail.ring[self.avail_idx].set(head);
                self.avail_idx += 1;
                self.vq.avail.idx.set(self.avail_idx as u16);
            }
            self.prev_desc = None;
            self
        }

        /// Add multiple readable frames (each is a separate chain).
        fn readable_frames(mut self, frames: &[&[u8]]) -> Self {
            for data in frames {
                self = self.readable(data).end_chain();
            }
            self
        }

        /// Add multiple writable buffers (each is a separate chain).
        fn writable_buffers(mut self, sizes: &[u32]) -> Self {
            for &size in sizes {
                self = self.writable(size).end_chain();
            }
            self
        }

        fn add_desc(&mut self, addr: u64, len: u32, flags: u16) {
            let idx = self.desc_idx;
            assert!(idx < QUEUE_SIZE as usize, "descriptor table overflow");
            self.desc_idx += 1;

            if let Some(prev) = self.prev_desc {
                let old_flags = self.vq.dtable[prev as usize].flags.get();
                self.vq.dtable[prev as usize].flags.set(old_flags | VIRTQ_DESC_F_NEXT);
                self.vq.dtable[prev as usize].next.set(idx as u16);
            } else {
                self.chain_head = Some(idx as u16);
            }

            self.vq.dtable[idx].set(addr, len, flags, 0);
            self.prev_desc = Some(idx as u16);
        }
    }

    /// Extension trait for VirtQueue setup.
    trait VirtQueueExt<'a> {
        fn builder<'b>(&'a self, mem: &'a GuestMemoryMmap) -> DescChainBuilder<'a, 'b>
        where
            'a: 'b;
    }

    impl<'a> VirtQueueExt<'a> for VirtQueue<'a> {
        fn builder<'b>(&'a self, mem: &'a GuestMemoryMmap) -> DescChainBuilder<'a, 'b>
        where
            'a: 'b,
        {
            DescChainBuilder::new(self, mem)
        }
    }

    // ============================================================================
    // TxQueueConsumer Tests
    // ============================================================================

    mod tx_queue_consumer_tests {
        use super::*;

        /// Create a TxQueueConsumer with a configured VirtQueue
        fn setup_tx_consumer(
            mem: &GuestMemoryMmap,
        ) -> (TxQueueConsumer, VirtQueue<'_>) {
            let vq = VirtQueue::new(GuestAddress(QUEUE_ADDR), mem, QUEUE_SIZE);
            let queue = vq.create_queue();
            let interrupt = create_interrupt();
            let consumer = TxQueueConsumer::new(queue, mem.clone(), interrupt);
            (consumer, vq)
        }

        #[test]
        fn test_new_consumer_is_empty() {
            let mem = create_memory();
            let (consumer, _vq) = setup_tx_consumer(&mem);

            assert_eq!(consumer.pending_count(), 0);
            assert!(!consumer.has_pending());
            assert!(consumer.frame_iovecs().is_empty());
        }

        #[test]
        fn test_feed_single_descriptor() {
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            vq.builder(&mem).readable(b"Hello, World!").end_chain();

            let added = consumer.feed_with_transform(10, |iovecs| {
                            });

            assert_eq!(added, 1);
            assert_eq!(consumer.pending_count(), 1);
            assert!(consumer.has_pending());

            let frames = consumer.frame_iovecs();
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].len(), 1);
            assert_eq!(&*frames[0][0], b"Hello, World!");
        }

        #[test]
        fn test_feed_chained_descriptors() {
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            // Chain of two descriptors (no end_chain between them)
            vq.builder(&mem)
                .readable(b"First")
                .readable(b"Second")
                .end_chain();

            let added = consumer.feed_with_transform(10, |iovecs| {
                            });

            assert_eq!(added, 1);
            assert_eq!(consumer.pending_count(), 1);

            let frames = consumer.frame_iovecs();
            assert_eq!(frames[0].len(), 2);
            assert_eq!(&*frames[0][0], b"First");
            assert_eq!(&*frames[0][1], b"Second");
        }

        #[test]
        fn test_feed_multiple_frames() {
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            vq.builder(&mem).readable_frames(&[b"Frame1", b"Frame2", b"Frame3"]);

            let added = consumer.feed_with_transform(10, |iovecs| {
                            });

            assert_eq!(added, 3);
            assert_eq!(consumer.pending_count(), 3);
            assert_eq!(consumer.frame_iovecs().len(), 3);
        }

        #[test]
        fn test_feed_respects_max_frames() {
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            vq.builder(&mem).readable_frames(&[b"F0", b"F1", b"F2", b"F3", b"F4"]);

            let added = consumer.feed_with_transform(2, |iovecs| {
                            });
            assert_eq!(added, 2);
            assert_eq!(consumer.pending_count(), 2);

            // Already at limit
            let added2 = consumer.feed_with_transform(2, |iovecs| {
                            });
            assert_eq!(added2, 0);
        }

        #[test]
        fn test_feed_transform_callback() {
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            vq.builder(&mem).readable(b"TestData12345").end_chain();

            let added = consumer.feed_with_transform(10, |iovecs| {
                // Skip 4 bytes (like skipping vnet header)
                let mut slices: &mut [IoSlice] = iovecs;
                IoSlice::advance_slices(&mut slices, 4);
                            });

            assert_eq!(added, 1);
        }

        #[test]
        fn test_consume_and_advance_bytes() {
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            vq.builder(&mem).readable_frames(&[b"FirstFrame", b"SecondFrame"]);

            consumer.feed_with_transform(10, |iovecs| {
                            });
            assert_eq!(consumer.pending_count(), 2);

            let result = consumer.consume(|frames| {
                let total: usize = frames
                    .iter()
                    .flat_map(|f| f.iter())
                    .map(|iov| iov.len())
                    .sum();
                Ok::<_, ()>(total)
            });

            assert_eq!(result, Ok(21)); // 10 + 11
            assert_eq!(consumer.pending_count(), 0);
        }

        #[test]
        fn test_consume_partial_bytes() {
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            vq.builder(&mem).readable_frames(&[b"Frame00000", b"Frame11111", b"Frame22222"]);

            consumer.feed_with_transform(10, |iovecs| {
                            });

            let result = consumer.consume(|_frames| Ok::<_, ()>(15));
            assert_eq!(result, Ok(15));
        }

        #[test]
        fn test_compact() {
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            // 5 frames of 4 bytes each
            vq.builder(&mem).readable_frames(&[b"test", b"test", b"test", b"test", b"test"]);

            consumer.feed_with_transform(10, |iovecs| {
                            });

            assert_eq!(consumer.frame_iovecs().len(), 5);

            // Advance 12 bytes = 3 complete frames
            consumer.advance_bytes(12);
            assert_eq!(consumer.pending_count(), 2);

            consumer.compact();
            assert_eq!(consumer.pending_count(), 2);
            assert_eq!(consumer.frame_iovecs().len(), 2);
        }

        #[test]
        fn test_empty_queue_returns_zero() {
            let mem = create_memory();
            let (mut consumer, _vq) = setup_tx_consumer(&mem);

            let added = consumer.feed_with_transform(10, |iovecs| {
                            });

            assert_eq!(added, 0);
            assert_eq!(consumer.pending_count(), 0);
            assert_eq!(consumer.consume(|_| Ok::<_, ()>(0)), Ok(0));
        }

        #[test]
        fn test_consume_error_preserves_pending() {
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            vq.builder(&mem).readable(b"TestData").end_chain();

            consumer.feed_with_transform(10, |iovecs| {
                            });

            let result: Result<usize, &str> = consumer.consume(|_| Err("EAGAIN"));
            assert!(result.is_err());
            assert_eq!(consumer.pending_count(), 1);
        }

        #[test]
        fn test_skips_write_only_descriptors() {
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            // Chain with readable then writable (writable should be skipped for TX)
            vq.builder(&mem)
                .readable(b"ReadData")
                .writable(100)
                .end_chain();

            consumer.feed_with_transform(10, |iovecs| {
                            });

            let frames = consumer.frame_iovecs();
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].len(), 1);
            assert_eq!(frames[0][0].len(), 8);
        }

        // ========================================================================
        // Header manipulation tests
        // ========================================================================

        #[test]
        fn test_remove_header_byte_tracking() {
            // Guest provides [header (12) | payload (100)].
            // Transform skips header. byte_count = 100 (payload only).
            // writev returns 100 → frame complete.
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            let mut data = vec![0x48u8; 12]; // header
            data.extend(vec![0x50; 100]); // payload

            vq.builder(&mem).readable(&data).end_chain();

            let added = consumer.feed_with_transform(10, |iovecs| {
                let mut slices: &mut [IoSlice] = iovecs;
                IoSlice::advance_slices(&mut slices, 12);
                            });
            assert_eq!(added, 1);

            let result = consumer.consume(|frames| {
                let total: usize = frames.iter()
                    .flat_map(|f| f.iter())
                    .map(|iov| iov.len())
                    .sum();
                assert_eq!(total, 100); // payload only
                Ok::<_, ()>(100)
            });

            assert_eq!(result, Ok(100));
            assert_eq!(consumer.pending_count(), 0);
        }

        #[test]
        fn test_add_header_byte_tracking() {
            // Guest provides [virtio_header (12) | payload (100)].
            // Transform skips virtio header, adds 4-byte frame length prefix.
            // byte_count = 4 + 100 = 104. writev returns 104 → frame complete.
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            let mut data = vec![0x48u8; 12];
            data.extend(vec![0x50; 100]);

            vq.builder(&mem).readable(&data).end_chain();

            let added = consumer.feed_with_transform(10, |iovecs| {
                let mut slices: &mut [IoSlice] = iovecs;
                IoSlice::advance_slices(&mut slices, 12);
                // After skip, total_len = 100 (payload only)
            });
            assert_eq!(added, 1);

            // Consume the payload (100 bytes after skipping 12-byte header)
            let result = consumer.consume(|_frames| Ok::<_, ()>(100));
            assert_eq!(result, Ok(100));
            assert_eq!(consumer.pending_count(), 0);
        }

        #[test]
        fn test_partial_send_with_header_removed() {
            // 2 frames: [header (10) | payload (50)] each.
            // After removing headers: 50 bytes per frame.
            // writev returns 75: completes frame 1 (50), partial frame 2 (25).
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            let mut data1 = vec![0x48u8; 10];
            data1.extend(vec![0x50; 50]);
            let mut data2 = vec![0x48u8; 10];
            data2.extend(vec![0x51; 50]);

            vq.builder(&mem)
                .readable(&data1).end_chain()
                .readable(&data2).end_chain();

            let added = consumer.feed_with_transform(10, |iovecs| {
                let mut slices: &mut [IoSlice] = iovecs;
                IoSlice::advance_slices(&mut slices, 10);
                            });
            assert_eq!(added, 2);

            let result = consumer.consume(|_frames| Ok::<_, ()>(75));
            assert_eq!(result, Ok(75));
            assert_eq!(consumer.pending_count(), 1); // frame 2 partial
        }

        #[test]
        fn test_multi_cycle_partial_writes_with_added_header() {
            // Tricky scenario: stream socket with added frame-length header.
            // Frame layout after transform: [frame_len (4) | payload (100)] = 104 bytes
            //
            // Cycle 1: writev returns 2 bytes (PARTIAL write of frame_len header!)
            // Cycle 2: writev returns 50 bytes (remaining 2 of header + 48 payload)
            // Cycle 3: writev returns 52 bytes (remaining 52 payload) → frame complete
            //
            // This tests resuming in the middle of a user-added header.
            let mem = create_memory();
            let (mut consumer, vq) = setup_tx_consumer(&mem);

            let mut data = vec![0x48u8; 12]; // virtio header (skipped)
            data.extend(vec![0x50; 100]); // payload

            vq.builder(&mem).readable(&data).end_chain();

            let added = consumer.feed_with_transform(10, |iovecs| {
                let mut slices: &mut [IoSlice] = iovecs;
                IoSlice::advance_slices(&mut slices, 12); // skip virtio header
                // After skip, total_len = 100 (payload only)
            });
            assert_eq!(added, 1);

            // Cycle 1: 2 bytes sent (partial)
            let result = consumer.consume(|_| Ok::<_, ()>(2));
            assert_eq!(result, Ok(2));
            assert_eq!(consumer.pending_count(), 1); // frame NOT complete

            // Cycle 2: 50 more bytes (total 52)
            let result = consumer.consume(|_| Ok::<_, ()>(50));
            assert_eq!(result, Ok(50));
            assert_eq!(consumer.pending_count(), 1); // still not complete (52 < 100)

            // Cycle 3: remaining 48 bytes
            let result = consumer.consume(|_| Ok::<_, ()>(48));
            assert_eq!(result, Ok(48));
            assert_eq!(consumer.pending_count(), 0); // frame complete (2+50+48=100)
        }

        #[test]
        fn test_multi_cycle_multiple_frames() {
            // 3 frames of 40 bytes each (after header removal) = 120 bytes total.
            // Cycle 1: 25 bytes (partial frame 1)
            // Cycle 2: 60 bytes (completes frame 1, completes frame 2, partial frame 3)
            // Cycle 3: EAGAIN (no progress)
            // Cycle 4: 35 bytes (completes frame 3)
            let mem = create_memory();
            let harness = VirtQueueHarness::new(&mem);

            // Add 3 frames using harness (simulates guest driver adding descriptors)
            let mut data = vec![0x48u8; 10]; // 10-byte header
            data.extend(vec![0x50; 40]); // 40-byte payload
            harness.add_readable(&data);
            harness.add_readable(&data);
            harness.add_readable(&data);

            let queue = harness.create_queue();
            let interrupt = create_interrupt();
            let mut consumer = TxQueueConsumer::new(queue, mem.clone(), interrupt);

            let added = consumer.feed_with_transform(10, |iovecs| {
                let mut slices: &mut [IoSlice] = iovecs;
                IoSlice::advance_slices(&mut slices, 10); // skip 10-byte header
                            });
            assert_eq!(added, 3);
            assert_eq!(consumer.pending_count(), 3);

            // Cycle 1: 25 bytes (partial frame 1)
            consumer.consume(|_| Ok::<_, ()>(25)).unwrap();
            assert_eq!(consumer.pending_count(), 3); // no frame complete yet

            // Cycle 2: 60 bytes → total 85 bytes
            // Frame 1: 40 bytes (complete at 40)
            // Frame 2: 40 bytes (complete at 80)
            // Frame 3: 5 bytes into it (at 85)
            consumer.consume(|_| Ok::<_, ()>(60)).unwrap();
            assert_eq!(consumer.pending_count(), 1); // frames 1,2 complete

            // Cycle 3: EAGAIN
            let result: Result<usize, &str> = consumer.consume(|_| Err("EAGAIN"));
            assert!(result.is_err());
            assert_eq!(consumer.pending_count(), 1); // still pending

            // Cycle 4: 35 bytes (completes frame 3)
            consumer.consume(|_| Ok::<_, ()>(35)).unwrap();
            assert_eq!(consumer.pending_count(), 0); // all done
        }

        #[test]
        fn test_stop_resume_across_compact() {
            // Feed 2 frames, partial send, compact, feed more, continue.
            // This tests that state is preserved when guest adds more descriptors mid-stream.
            let mem = create_memory();
            let harness = VirtQueueHarness::new(&mem);

            // First batch: 2 frames of 30 bytes each
            let data = vec![0x50u8; 30];
            harness.add_readable(&data);
            harness.add_readable(&data);

            let queue = harness.create_queue();
            let interrupt = create_interrupt();
            let mut consumer = TxQueueConsumer::new(queue, mem.clone(), interrupt);

            consumer.feed_with_transform(10, |iovecs| {
                            });
            assert_eq!(consumer.pending_count(), 2);

            // Send 45 bytes (frame 1 complete, 15 into frame 2)
            consumer.consume(|_| Ok::<_, ()>(45)).unwrap();
            assert_eq!(consumer.pending_count(), 1);

            // Compact removes completed frame 1
            // (compact is called automatically in consume, but let's verify state)

            // Guest adds more descriptors (simulating queue refill)
            harness.add_readable(&data); // frame 3

            consumer.feed_with_transform(10, |iovecs| {
                            });
            assert_eq!(consumer.pending_count(), 2); // frame 2 (partial) + frame 3

            // Send remaining 15 of frame 2 + all 30 of frame 3 = 45
            consumer.consume(|_| Ok::<_, ()>(45)).unwrap();
            assert_eq!(consumer.pending_count(), 0);
        }
    }

    // ============================================================================
    // RxQueueProvider Tests
    // ============================================================================

    mod rx_queue_provider_tests {
        use super::*;

        /// Create an RxQueueProvider with a configured VirtQueue
        fn setup_rx_provider(
            mem: &GuestMemoryMmap,
        ) -> (RxQueueProducer, VirtQueue<'_>) {
            let vq = VirtQueue::new(GuestAddress(QUEUE_ADDR), mem, QUEUE_SIZE);
            let queue = vq.create_queue();
            let interrupt = create_interrupt();
            let provider = RxQueueProducer::new(queue, mem.clone(), interrupt);
            (provider, vq)
        }

        #[test]
        fn test_new_provider_is_empty() {
            let mem = create_memory();
            let (provider, _vq) = setup_rx_provider(&mem);

            assert_eq!(provider.pending_count(), 0);
        }

        #[test]
        fn test_feed_single_writable_descriptor() {
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            vq.builder(&mem).writable(1500).end_chain();

            let added = provider.feed(10);

            assert_eq!(added, 1);
            assert_eq!(provider.pending_count(), 1);
        }

        #[test]
        fn test_feed_chained_writable_descriptors() {
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            // Chain of 2 writable descriptors
            vq.builder(&mem)
                .writable(512)
                .writable(1024)
                .end_chain();

            let added = provider.feed(10);

            assert_eq!(added, 1);
            assert_eq!(provider.pending_count(), 1);

            // Verify buffer structure via produce
            provider.produce(|chains, _completer| {
                assert_eq!(chains.len(), 1);
                assert_eq!(chains[0].len(), 2);
                assert_eq!(chains[0][0].len(), 512);
                assert_eq!(chains[0][1].len(), 1024);
                // Don't mark anything as finished
            });
        }

        #[test]
        fn test_feed_multiple_buffers() {
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            vq.builder(&mem).writable_buffers(&[1500, 1500, 1500]);

            let added = provider.feed(10);

            assert_eq!(added, 3);
            assert_eq!(provider.pending_count(), 3);
        }

        #[test]
        fn test_feed_respects_max_frames() {
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            vq.builder(&mem).writable_buffers(&[1500, 1500, 1500, 1500, 1500]);

            let added = provider.feed(2);

            assert_eq!(added, 2);
            assert_eq!(provider.pending_count(), 2);
        }

        #[test]
        fn test_produce_fills_buffers() {
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            vq.builder(&mem).writable_buffers(&[1500, 1500]);

            provider.feed(10);
            assert_eq!(provider.pending_count(), 2);

            let completed = provider.produce(|chains, completer| {
                chains[0][0][..17].copy_from_slice(b"Received packet 1");
                completer.complete(&mut chains[0], 0, 17);

                chains[1][0][..17].copy_from_slice(b"Received packet 2");
                completer.complete(&mut chains[1], 1, 17);
            });

            assert_eq!(completed, 2);
            assert_eq!(provider.pending_count(), 0);

            assert_eq!(&read_data(&mem, GuestAddress(DATA_ADDR), 17), b"Received packet 1");
            assert_eq!(&read_data(&mem, GuestAddress(DATA_ADDR + 1500), 17), b"Received packet 2");
        }

        #[test]
        fn test_produce_partial_fill() {
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            vq.builder(&mem).writable_buffers(&[1500, 1500, 1500]);

            provider.feed(10);

            let completed = provider.produce(|chains, completer| {
                chains[0][0][..10].copy_from_slice(b"0123456789");
                completer.complete(&mut chains[0], 0, 10);

                chains[1][0][..10].copy_from_slice(b"ABCDEFGHIJ");
                completer.complete(&mut chains[1], 1, 10);

                // Third not filled - don't call complete
            });

            assert_eq!(completed, 2);
            assert_eq!(provider.pending_count(), 1);
        }

        #[test]
        fn test_produce_keeps_unused_buffers() {
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            vq.builder(&mem).writable_buffers(&[1500, 1500]);

            provider.feed(10);

            // First produce: no data received (EAGAIN-like)
            let completed = provider.produce(|_chains, _completer| {
                // Don't complete anything
            });
            assert_eq!(completed, 0);
            assert_eq!(provider.pending_count(), 2);

            // Second produce: fill one buffer
            let completed = provider.produce(|chains, completer| {
                chains[0][0][..5].copy_from_slice(b"Hello");
                completer.complete(&mut chains[0], 0, 5);
                // Don't complete second buffer
            });
            assert_eq!(completed, 1);
            assert_eq!(provider.pending_count(), 1);
        }

        #[test]
        fn test_empty_queue_returns_zero() {
            let mem = create_memory();
            let (mut provider, _vq) = setup_rx_provider(&mem);

            assert_eq!(provider.feed(10), 0);
            assert_eq!(provider.pending_count(), 0);
            assert_eq!(provider.produce(|_chains, _completer| {}), 0);
        }

        #[test]
        fn test_skips_read_only_descriptors() {
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            // Chain with readable then writable (readable should be skipped for RX)
            vq.builder(&mem)
                .readable(b"ignored")
                .writable(1400)
                .end_chain();

            provider.feed(10);

            // Verify buffer structure via produce
            provider.produce(|chains, _completer| {
                assert_eq!(chains.len(), 1);
                assert_eq!(chains[0].len(), 1);
                assert_eq!(chains[0][0].len(), 1400);
            });
        }

        #[test]
        fn test_chained_buffer_receive() {
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            // Chain of 3 writable descriptors forming one buffer
            vq.builder(&mem)
                .writable(100)
                .writable(200)
                .writable(300)
                .end_chain();

            provider.feed(10);
            assert_eq!(provider.pending_count(), 1);

            let completed = provider.produce(|chains, completer| {
                chains[0][0].copy_from_slice(&[0xAA; 100]);
                chains[0][1].copy_from_slice(&[0xBB; 200]);
                chains[0][2].copy_from_slice(&[0xCC; 300]);
                completer.complete(&mut chains[0], 0, 600);
            });

            assert_eq!(completed, 1);

            // Builder spaces each descriptor by max(size, 0x100):
            // - desc 0: DATA_ADDR + 0x000
            // - desc 1: DATA_ADDR + 0x100
            // - desc 2: DATA_ADDR + 0x200
            assert_eq!(read_data(&mem, GuestAddress(DATA_ADDR), 100), vec![0xAA; 100]);
            assert_eq!(read_data(&mem, GuestAddress(DATA_ADDR + 0x100), 200), vec![0xBB; 200]);
            assert_eq!(read_data(&mem, GuestAddress(DATA_ADDR + 0x200), 300), vec![0xCC; 300]);
        }

        #[test]
        fn test_multiple_produce_cycles() {
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            vq.builder(&mem).writable_buffers(&[1500, 1500, 1500, 1500]);

            // First feed: get 2 buffers
            provider.feed(2);
            assert_eq!(provider.pending_count(), 2);

            // First produce: fill 1
            let completed = provider.produce(|chains, completer| {
                chains[0][0][..4].copy_from_slice(b"pkt1");
                completer.complete(&mut chains[0], 0, 4);
                // Don't complete second
            });
            assert_eq!(completed, 1);
            assert_eq!(provider.pending_count(), 1);

            // Second feed: get 1 more (1 pending + 1 new = 2)
            provider.feed(2);
            assert_eq!(provider.pending_count(), 2);

            // Second produce: fill both
            let completed = provider.produce(|chains, completer| {
                for (i, chain) in chains.iter_mut().enumerate() {
                    chain[0][..4].copy_from_slice(b"data");
                    completer.complete(chain, i, 4);
                }
            });
            assert_eq!(completed, 2);
            assert_eq!(provider.pending_count(), 0);
        }

        #[test]
        fn test_selective_completion() {
            // Verify that only explicitly completed chains are removed.
            // With the new API, completion is explicit via completer.finish().
            let mem = create_memory();
            let (mut provider, vq) = setup_rx_provider(&mem);

            vq.builder(&mem).writable_buffers(&[1500, 1500, 1500]);

            provider.feed(10);
            assert_eq!(provider.pending_count(), 3);

            // Complete only buffer 0, leave 1 and 2 pending
            let completed = provider.produce(|chains, completer| {
                chains[0][0][..4].copy_from_slice(b"pkt0");
                completer.complete(&mut chains[0], 0, 100);
                // Don't complete buffers 1 and 2
            });

            assert_eq!(completed, 1);
            assert_eq!(provider.pending_count(), 2); // buffers 1 and 2 kept
        }
    }

}

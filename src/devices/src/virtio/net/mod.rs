// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{io, mem, result};
use virtio_bindings::virtio_net::virtio_net_hdr_v1;

pub const MAX_BUFFER_SIZE: usize = 65562;
pub const QUEUE_SIZE: u16 = 1024;
pub const NUM_QUEUES: usize = 2;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];
// The index of the rx queue from Net device queues/queues_evts vector.
pub const RX_INDEX: usize = 0;
// The index of the tx queue from Net device queues/queues_evts vector.
pub const TX_INDEX: usize = 1;

mod backend;
pub mod device;
mod unixgram;
mod unixstream;
mod worker;

fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

// This initializes to all 0 the virtio_net_hdr part of a buf and return the length of the header
// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2050006
fn write_virtio_net_hdr(buf: &mut [u8]) -> usize {
    let len = vnet_hdr_len();
    buf[0..len].fill(0);
    len
}

pub use self::device::Net;
#[derive(Debug)]
pub enum Error {
    /// EventFd error.
    EventFd(io::Error),
}

pub type Result<T> = result::Result<T, Error>;

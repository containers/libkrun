// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generic chain memory representation trait for TX/RX queue operations.
//!
//! This trait abstracts over how iovecs are represented per descriptor chain,
//! allowing different backends to use optimized representations (e.g., mmsghdr for sendmmsg).

use libc::iovec;

/// Base trait for descriptor chain memory representation.
///
/// Construction is not part of the trait - each representation type provides its own
/// constructor.
pub trait ChainsMemoryRepr: Sized + Send {
    /// User-defined metadata stored alongside each chain (e.g., Vec capacity).
    type Meta: Default;

    /// Number of slices in this chain.
    fn len(&self) -> usize;

    /// Check if empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes across all slices.
    fn total_bytes(&self) -> usize;

    /// Clear/reset and drop resources.
    fn clear(&mut self, meta: &mut Self::Meta);
}

/// Trait for representation types that support advancing (consuming bytes from front).
///
/// This is used by RX operations where the caller tracks byte counts manually
/// (e.g., via readv return values) rather than having the kernel fill them in.
pub trait AdvanceBytes {
    /// Advance slices by removing consumed bytes from the front.
    fn advance(&mut self, bytes: usize);
}

/// Trait for representation types that support truncating (limiting total bytes).
///
/// This is useful for RX operations where you want to limit how many bytes
/// can be received into a buffer.
pub trait TruncateBytes {
    /// Truncate slices to limit total bytes to `max_bytes`.
    fn truncate_bytes(&mut self, max_bytes: usize);
}

/// Wrapper around `Vec<iovec>` that implements `Send`.
///
/// # Safety
/// The raw pointers in `iovec` point to guest memory managed by the owning
/// `TxQueueConsumer`/`RxQueueProducer`. The memory is pinned and the struct
/// lifetime ensures the pointers remain valid. Transferring to another thread
/// is safe because we transfer ownership of the entire container.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct IovecVec(pub Vec<iovec>);

// Safety: See struct-level documentation
unsafe impl Send for IovecVec {}

// ChainsMemoryRepr implemented for IovecVec - the default representation type.
// Raw iovec has no lifetime, avoiding the need for fake 'static lifetimes.
impl ChainsMemoryRepr for IovecVec {
    type Meta = ();

    fn len(&self) -> usize {
        self.0.len()
    }

    fn total_bytes(&self) -> usize {
        self.0.iter().map(|s| s.iov_len).sum()
    }

    fn clear(&mut self, _meta: &mut ()) {
        self.0.clear();
    }
}

impl AdvanceBytes for IovecVec {
    fn advance(&mut self, bytes: usize) {
        let mut remaining = bytes;
        while remaining > 0 && !self.0.is_empty() {
            let first_len = self.0[0].iov_len;
            if first_len <= remaining {
                self.0.remove(0);
                remaining -= first_len;
            } else {
                let first = &mut self.0[0];
                first.iov_base = unsafe { (first.iov_base as *mut u8).add(remaining) as *mut _ };
                first.iov_len -= remaining;
                remaining = 0;
            }
        }
    }
}

impl TruncateBytes for IovecVec {
    fn truncate_bytes(&mut self, max_bytes: usize) {
        let mut remaining = max_bytes;
        let mut keep = 0;
        for iov in self.0.iter_mut() {
            if remaining == 0 {
                break;
            }
            if iov.iov_len <= remaining {
                remaining -= iov.iov_len;
                keep += 1;
            } else {
                iov.iov_len = remaining;
                remaining = 0;
                keep += 1;
            }
        }
        self.0.truncate(keep);
    }
}

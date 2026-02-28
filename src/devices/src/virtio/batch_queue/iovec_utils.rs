// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Utilities for working with iovec slices.

use libc::iovec;
use std::io::IoSliceMut;

/// Calculate total length of iovec slices.
/// Works with both IoSlice and IoSliceMut.
pub fn iovecs_len<T: std::ops::Deref<Target = [u8]>>(slices: &[T]) -> usize {
    slices.iter().map(|s| s.len()).sum()
}

/// Write data to iovecs, spanning multiple buffers if needed.
pub fn write_to_iovecs(slices: &mut [IoSliceMut], data: &[u8]) -> usize {
    let mut written = 0;
    for iov in slices.iter_mut() {
        let remaining = data.len() - written;
        if remaining == 0 {
            break;
        }
        let take = remaining.min(iov.len());
        iov[..take].copy_from_slice(&data[written..written + take]);
        written += take;
    }
    written
}

/// Advance iovecs in place by `bytes`, removing fully consumed buffers (Vec version).
///
/// Works with Vec, removing consumed iovecs from the front and
/// adjusting the first remaining iovec's pointer/length as needed.
pub fn advance_iovecs_vec(iovecs: &mut Vec<IoSliceMut<'_>>, bytes: usize) {
    let mut remaining = bytes;
    while remaining > 0 && !iovecs.is_empty() {
        let first_len = iovecs[0].len();
        if first_len <= remaining {
            iovecs.remove(0);
            remaining -= first_len;
        } else {
            let ptr = iovecs[0].as_mut_ptr();
            let new_len = first_len - remaining;
            // Safety: advancing pointer within same allocation
            let new_slice = unsafe { std::slice::from_raw_parts_mut(ptr.add(remaining), new_len) };
            iovecs[0] = IoSliceMut::new(new_slice);
            remaining = 0;
        }
    }
}

/// Advance IoSlice Vec in place by `bytes`, removing fully consumed buffers.
///
/// Works with Vec<IoSlice>, removing consumed iovecs from the front and
/// adjusting the first remaining iovec's pointer/length as needed.
pub fn advance_tx_iovecs_vec(iovecs: &mut Vec<std::io::IoSlice<'_>>, bytes: usize) {
    let mut remaining = bytes;
    while remaining > 0 && !iovecs.is_empty() {
        let first_len = iovecs[0].len();
        if first_len <= remaining {
            iovecs.remove(0);
            remaining -= first_len;
        } else {
            let ptr = iovecs[0].as_ptr();
            let new_len = first_len - remaining;
            // Safety: advancing pointer within same allocation
            let new_slice = unsafe { std::slice::from_raw_parts(ptr.add(remaining), new_len) };
            iovecs[0] = std::io::IoSlice::new(new_slice);
            remaining = 0;
        }
    }
}

/// Advance raw iovecs in place by `bytes`, removing fully consumed buffers.
///
/// Works directly on `Vec<iovec>` without going through `IoSliceMut`, avoiding
/// provenance issues when the iovecs originate from read-only memory (e.g., TX).
pub fn advance_raw_iovecs(iovecs: &mut Vec<iovec>, bytes: usize) {
    let mut remaining = bytes;
    while remaining > 0 && !iovecs.is_empty() {
        let first_len = iovecs[0].iov_len;
        if first_len <= remaining {
            iovecs.remove(0);
            remaining -= first_len;
        } else {
            // Safety: advancing pointer within same allocation
            iovecs[0].iov_base = unsafe { (iovecs[0].iov_base as *mut u8).add(remaining) as _ };
            iovecs[0].iov_len = first_len - remaining;
            remaining = 0;
        }
    }
}

/// Truncate iovecs in place to max_bytes total, returning the usable slice.
pub fn truncate_iovecs<'a, 'b>(
    slices: &'a mut [IoSliceMut<'b>],
    max_bytes: usize,
) -> &'a mut [IoSliceMut<'b>] {
    let mut total: usize = 0;
    for (i, slice) in slices.iter_mut().enumerate() {
        let new_total = total.saturating_add(slice.len());

        if new_total >= max_bytes {
            // total <= max_bytes here (otherwise we'd have returned in a previous iteration),
            // so this subtraction cannot underflow
            let take = max_bytes - total;
            // Last iovec is empty so we don't include it in the and
            if take == 0 {
                return &mut slices[..i];
            }

            let ptr = slice.as_mut_ptr();
            // SAFETY: `take <= len` because we only enter this branch when
            // `total + len >= max_bytes`, which means `max_bytes - total <= len`.
            // The pointer `ptr` is valid for `len` bytes, so it's valid for `take` bytes.
            *slice = IoSliceMut::new(unsafe { std::slice::from_raw_parts_mut(ptr, take) });
            return &mut slices[..=i];
        }
        total = new_total;
    }
    slices
}

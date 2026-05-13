use std::sync::atomic::{AtomicU64, Ordering};

use super::fuse;

/// Allocates unique FUSE inode numbers.
///
/// FUSE inode numbers are opaque identifiers with two reserved values:
///   - `0` — invalid / negative-entry cache sentinel (never allocated)
///   - `1` (`ROOT_ID`) — the root directory of the filesystem
///
/// All other numbers are allocated sequentially starting from `ROOT_ID + 1`.
/// The allocator is `Send + Sync` and safe to share across threads.
pub struct InodeAllocator {
    next: AtomicU64,
}

impl InodeAllocator {
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(fuse::ROOT_ID + 1),
        }
    }

    /// Allocate the next inode number. Each call returns a unique value.
    pub fn next(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

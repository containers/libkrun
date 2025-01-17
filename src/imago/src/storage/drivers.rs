//! Internal functionality for storage drivers.

use crate::misc_helpers::Overlaps;
use crate::vector_select::FutureVector;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::oneshot;

/// Helper object for the [`StorageExt`](crate::StorageExt) implementation.
///
/// State such as write blockers needs to be kept somewhere, and instead of introducing a wrapper
/// (that might be bypassed), we store it directly in the [`Storage`](crate::Storage) objects so it
/// cannot be bypassed (at least when using the [`StorageExt`](crate::StorageExt) methods).
#[derive(Debug, Default)]
pub struct CommonStorageHelper {
    /// Current in-flight write that allow concurrent writes to the same region.
    ///
    /// Normal non-async RwLock, so do not await while locked!
    weak_write_blockers: std::sync::RwLock<RangeBlockedList>,

    /// Current in-flight write that do not allow concurrent writes to the same region.
    strong_write_blockers: std::sync::RwLock<RangeBlockedList>,
}

/// A list of ranges blocked for some kind of concurrent access.
///
/// Depending on the use, some will block all concurrent access (i.e. serializing writes will block
/// both serializing and non-serializing writes (strong blockers)), while others will only block a
/// subset (non-serializing writes will only block serializing writes (weak blockers)).
#[derive(Debug, Default)]
struct RangeBlockedList {
    /// The list of ranges.
    ///
    /// Serializing writes (strong write blockers) are supposed to be rare, so it is important that
    /// entering and removing items into/from this list is cheap, not that iterating it is.
    blocked: Vec<Arc<RangeBlocked>>,
}

/// A range blocked for some kind of concurrent access.
#[derive(Debug)]
struct RangeBlocked {
    /// The range.
    range: Range<u64>,

    /// List of requests awaiting the range to become unblocked.
    ///
    /// When the corresponding `RangeBlockedGuard` is dropped, these will all be awoken (via
    /// `oneshot::Sender::send(())`).
    ///
    /// Normal non-async mutex, so do not await while locked!
    waitlist: std::sync::Mutex<Vec<oneshot::Sender<()>>>,

    /// Index in the corresponding `RangeBlockedList.blocked` list, so it can be dropped quickly.
    ///
    /// (When the corresponding `RangeBlockedGuard` is dropped, this entry is swap-removed from the
    /// `blocked` list, and the other entry taking its place has its `index` updated.)
    ///
    /// Only access under `blocked` lock!
    index: AtomicUsize,
}

/// Keeps a `RangeBlocked` alive.
///
/// When dropped, removes the `RangeBlocked` from its list, and wakes all requests in the `waitlist`.
#[derive(Debug)]
pub struct RangeBlockedGuard<'a> {
    /// List where this blocker resides.
    list: &'a std::sync::RwLock<RangeBlockedList>,

    /// `Option`, so `drop()` can `take()` it and unwrap the `Arc`.
    ///
    /// Consequently, do not clone: Must have refcount 1 when dropped.  (The only clone must be in
    /// `self.list.blocked`, under index `self.block.index`.)
    block: Option<Arc<RangeBlocked>>,
}

impl CommonStorageHelper {
    /// Await concurrent strong write blockers for the given range.
    ///
    /// Strong write blockers are set up for writes that must not be intersected by any other
    /// write.  Await such intersecting concurrent write requests, and return a guard that will
    /// delay such new writes until the guard is dropped.
    pub async fn weak_write_blocker(&self, range: Range<u64>) -> RangeBlockedGuard<'_> {
        let mut intersecting = FutureVector::new();

        let range_block = {
            // Acquire write lock first
            let mut weak = self.weak_write_blockers.write().unwrap();
            let strong = self.strong_write_blockers.read().unwrap();

            strong.collect_intersecting_await_futures(&range, &mut intersecting);
            weak.block(range)
        };

        intersecting.discarding_join().await.unwrap();

        RangeBlockedGuard {
            list: &self.weak_write_blockers,
            block: Some(range_block),
        }
    }

    /// Await any concurrent write request for the given range.
    ///
    /// Block the given range for any concurrent write requests until the returned guard object is
    /// dropped.  Existing requests are awaited, and new ones will be delayed.
    pub async fn strong_write_blocker(&self, range: Range<u64>) -> RangeBlockedGuard<'_> {
        let mut intersecting = FutureVector::new();

        let range_block = {
            // Acquire write lock first
            let mut strong = self.strong_write_blockers.write().unwrap();
            let weak = self.weak_write_blockers.read().unwrap();

            weak.collect_intersecting_await_futures(&range, &mut intersecting);
            strong.collect_intersecting_await_futures(&range, &mut intersecting);
            strong.block(range)
        };

        intersecting.discarding_join().await.unwrap();

        RangeBlockedGuard {
            list: &self.strong_write_blockers,
            block: Some(range_block),
        }
    }
}

impl RangeBlockedList {
    /// Collects futures to await intersecting request.
    ///
    /// Adds a future to `future_vector` for every intersecting request; awaiting that future will
    /// await the request.
    fn collect_intersecting_await_futures(
        &self,
        check_range: &Range<u64>,
        future_vector: &mut FutureVector<(), oneshot::error::RecvError, oneshot::Receiver<()>>,
    ) {
        for range_block in self.blocked.iter() {
            if range_block.range.overlaps(check_range) {
                let (s, r) = oneshot::channel::<()>();
                range_block.waitlist.lock().unwrap().push(s);
                future_vector.push(r);
            }
        }
    }

    /// Enter a new blocked range into the list.
    ///
    /// This only blocks new requests, old requests must separately be awaited by awaiting all
    /// futures returned by `collect_intersecting_await_futures()`.
    fn block(&mut self, range: Range<u64>) -> Arc<RangeBlocked> {
        let range_block = Arc::new(RangeBlocked {
            range,
            waitlist: Default::default(),
            index: self.blocked.len().into(),
        });
        self.blocked.push(Arc::clone(&range_block));
        range_block
    }
}

impl Drop for RangeBlockedGuard<'_> {
    fn drop(&mut self) {
        let block = self.block.take().unwrap();

        {
            let mut list = self.list.write().unwrap();
            let i = block.index.load(Ordering::Relaxed);
            let removed = list.blocked.swap_remove(i);
            debug_assert!(Arc::ptr_eq(&removed, &block));
            if let Some(block) = list.blocked.get(i) {
                block.index.store(i, Ordering::Relaxed);
            }
        }

        let block = Arc::into_inner(block).unwrap();
        let waitlist = block.waitlist.into_inner().unwrap();
        for waiting in waitlist {
            waiting.send(()).unwrap();
        }
    }
}

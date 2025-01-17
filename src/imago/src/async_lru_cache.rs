//! Provides a least-recently-used cache with async access.
//!
//! To operate, this cache is bound to an I/O back-end object that provides the loading and
//! flushing of cache entries.
//!
//! Also supports inter-cache dependency, e.g. for when the qcow2 L2 table cache needs to be
//! flushed before the refblock cache, because some clusters were freed (so the L2 references need
//! to be cleared before the clusters are deallocated).

#![allow(dead_code)]

use crate::vector_select::FutureVector;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard, RwLock, RwLockWriteGuard};
use tracing::{error, span, trace, Level};

/// Cache entry structure, wrapping the cached object.
pub(crate) struct AsyncLruCacheEntry<V> {
    /// Cached object.
    ///
    /// Always set during operation, only cleared when trying to unwrap the `Arc` on eviction.
    value: Option<Arc<V>>,

    /// When this entry was last accessed.
    last_used: AtomicUsize,
}

/// Least-recently-used cache with async access.
struct AsyncLruCacheInner<
    Key: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync,
    Value: Send + Sync,
    IoBackend: AsyncLruCacheBackend<Key = Key, Value = Value>,
> {
    /// I/O back-end that performs loading and flushing of cache entries.
    backend: IoBackend,

    /// Cache entries.
    map: RwLock<HashMap<Key, AsyncLruCacheEntry<Value>>>,

    /// Flush dependencies (flush these first).
    flush_before: Mutex<Vec<Arc<dyn FlushableCache>>>,

    /// Monotonically increasing counter to generate “timestamps”.
    lru_timer: AtomicUsize,

    /// Upper limit of how many entries to cache.
    limit: usize,
}

/// Least-recently-used cache with async access.
///
/// Keeps the least recently used entries up to a limited count.  Accessing and flushing is
/// async-aware.
///
/// `K` is the key used to uniquely identify cache entries, `V` is the cached data.
pub(crate) struct AsyncLruCache<
    K: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync,
    V: Send + Sync,
    B: AsyncLruCacheBackend<Key = K, Value = V>,
>(Arc<AsyncLruCacheInner<K, V, B>>);

/// Internal trait used to implement inter-cache flush dependencies.
#[async_trait(?Send)]
trait FlushableCache: Send + Sync {
    /// Flush the cache.
    async fn flush(&self) -> io::Result<()>;

    /// Check of circular dependencies.
    ///
    /// Return `true` if (and only if) `other` is already a transitive dependency of `self`.
    async fn check_circular(&self, other: &Arc<dyn FlushableCache>) -> bool;
}

/// Provides loading and flushing for cache entries.
pub(crate) trait AsyncLruCacheBackend: Send + Sync {
    /// Key type.
    type Key: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync;
    /// Value (object) type.
    type Value: Send + Sync;

    /// Load the given object.
    #[allow(async_fn_in_trait)] // No need for Send
    async fn load(&self, key: Self::Key) -> io::Result<Self::Value>;

    /// Flush the given object.
    ///
    /// The implementation should itself check whether the object is dirty; `flush()` is called for
    /// all evicted cache entries, regardless of whether they actually are dirty or not.
    #[allow(async_fn_in_trait)] // No need for Send
    async fn flush(&self, key: Self::Key, value: Arc<Self::Value>) -> io::Result<()>;
}

impl<
        K: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync,
        V: Send + Sync,
        B: AsyncLruCacheBackend<Key = K, Value = V>,
    > AsyncLruCache<K, V, B>
{
    /// Create a new cache.
    ///
    /// `size` is the maximum number of entries to keep in the cache.
    pub fn new(backend: B, size: usize) -> Self {
        AsyncLruCache(Arc::new(AsyncLruCacheInner {
            backend,
            map: Default::default(),
            flush_before: Default::default(),
            lru_timer: AtomicUsize::new(0),
            limit: size,
        }))
    }

    /// Retrieve an entry from the cache.
    ///
    /// If there is no entry yet, run `read()` to generate it.  If then there are more entries in
    /// the cache than its limit, flush out the oldest entry via `flush()`.
    pub async fn get_or_insert(&self, key: K) -> io::Result<Arc<V>> {
        self.0.get_or_insert(key).await
    }

    /// Force-insert the given object into the cache.
    ///
    /// If there is an existing object under that key, it is flushed first.
    pub async fn insert(&self, key: K, value: Arc<V>) -> io::Result<()> {
        self.0.insert(key, value).await
    }

    /// Flush all cache entries.
    ///
    /// Those entries are not evicted, but remain in the cache.
    pub async fn flush(&self) -> io::Result<()> {
        self.0.flush().await
    }
}

impl<
        K: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync + 'static,
        V: Send + Sync + 'static,
        B: AsyncLruCacheBackend<Key = K, Value = V> + 'static,
    > AsyncLruCache<K, V, B>
{
    /// Set up a flush dependency.
    ///
    /// Ensure that before anything in this cache is flushed, `flush_before` is flushed first.
    pub async fn depend_on<
        K2: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync + 'static,
        V2: Send + Sync + 'static,
        B2: AsyncLruCacheBackend<Key = K2, Value = V2> + 'static,
    >(
        &self,
        other: &AsyncLruCache<K2, V2, B2>,
    ) -> io::Result<()> {
        let _span = span!(
            Level::TRACE,
            "AsyncLruCache::depend_on",
            self = Arc::as_ptr(&self.0) as usize,
            other = Arc::as_ptr(&other.0) as usize
        )
        .entered();

        let cloned: Arc<AsyncLruCacheInner<K2, V2, B2>> = Arc::clone(&other.0);
        let cloned: Arc<dyn FlushableCache> = cloned;

        loop {
            {
                let mut locked = self.0.flush_before.lock().await;
                // Shouldn’t be long, so linear search seems fine
                if locked.iter().any(|x| Arc::ptr_eq(x, &cloned)) {
                    break;
                }

                let self_arc: Arc<AsyncLruCacheInner<K, V, B>> = Arc::clone(&self.0);
                let self_arc: Arc<dyn FlushableCache> = self_arc;
                if !other.0.check_circular(&self_arc).await {
                    trace!("No circular dependency, entering new dependency");
                    locked.push(cloned);
                    break;
                }
            }

            trace!("Circular dependency detected, flushing other cache first");

            other.0.flush().await?;
        }

        Ok(())
    }
}

impl<
        K: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync,
        V: Send + Sync,
        B: AsyncLruCacheBackend<Key = K, Value = V>,
    > AsyncLruCacheInner<K, V, B>
{
    /// Flush all dependencies.
    ///
    /// Flush all caches that must be flushed before this one.  Remove all successfully flushed
    /// caches from our dependency list.
    ///
    /// Call with a guard that should be dropped only after this cache is flushed, so that no new
    /// dependencies can enter while we are still flushing this cache.
    async fn flush_dependencies(
        flush_before: &mut MutexGuard<'_, Vec<Arc<dyn FlushableCache>>>,
    ) -> io::Result<()> {
        let _span = span!(Level::TRACE, "AsyncLruCache::flush_dependencies").entered();

        while let Some(dep) = flush_before.pop() {
            trace!("Flushing dependency {:?}", Arc::as_ptr(&dep) as *const _);
            if let Err(err) = dep.flush().await {
                flush_before.push(dep);
                return Err(err);
            }
        }
        Ok(())
    }

    /// Ensure there is at least one free entry in the cache.
    ///
    /// Do this by evicting (flushing) existing entries, if necessary.
    async fn ensure_free_entry(
        &self,
        map: &mut RwLockWriteGuard<'_, HashMap<K, AsyncLruCacheEntry<V>>>,
    ) -> io::Result<()> {
        let _span = span!(
            Level::TRACE,
            "AsyncLruCache::ensure_free_entry",
            self = &self as *const _ as usize
        )
        .entered();

        while map.len() >= self.limit {
            trace!("{} / {} used", map.len(), self.limit);

            let now = self.lru_timer.load(Ordering::Relaxed);
            let (evicted_object, key, last_used) = loop {
                let oldest = map.iter().fold((0, None), |oldest, (key, entry)| {
                    // Cannot drop entries that are in use
                    if Arc::strong_count(entry.value()) > 1 {
                        return oldest;
                    }

                    let age = now.wrapping_sub(entry.last_used.load(Ordering::Relaxed));
                    if age >= oldest.0 {
                        (age, Some(*key))
                    } else {
                        oldest
                    }
                });

                let Some(oldest_key) = oldest.1 else {
                    error!("Cannot evict entry from cache; everything is in use");
                    return Err(io::Error::other(
                        "Cannot evict entry from cache; everything is in use",
                    ));
                };

                trace!(
                    "Removing entry with key {:?}, aged {}",
                    oldest_key,
                    oldest.0
                );

                let mut oldest_entry = map.remove(&oldest_key).unwrap();
                match Arc::try_unwrap(oldest_entry.value.take().unwrap()) {
                    Ok(object) => {
                        break (
                            object,
                            oldest_key,
                            oldest_entry.last_used.load(Ordering::Relaxed),
                        )
                    }
                    Err(arc) => {
                        trace!("Entry is still in use, retrying");

                        // Found a race, retry.
                        // (`Arc::strong_count()` should return `1` in the next iteration,
                        // filtering this entry out.)
                        oldest_entry.value = Some(arc);
                    }
                }
            };

            let mut dep_guard = self.flush_before.lock().await;
            Self::flush_dependencies(&mut dep_guard).await?;
            let obj = Arc::new(evicted_object);
            trace!("Flushing {key:?}");
            if let Err(err) = self.backend.flush(key, Arc::clone(&obj)).await {
                map.insert(
                    key,
                    AsyncLruCacheEntry {
                        value: Some(obj),
                        last_used: last_used.into(),
                    },
                );
                return Err(err);
            }
            let _ = Arc::into_inner(obj).expect("flush() must not clone the object");
        }

        Ok(())
    }

    /// Retrieve an entry from the cache.
    ///
    /// If there is no entry yet, run `read()` to generate it.  If then there are more entries in
    /// the cache than its limit, flush out the oldest entry via `flush()`.
    async fn get_or_insert(&self, key: K) -> io::Result<Arc<V>> {
        {
            let map = self.map.read().await;
            if let Some(entry) = map.get(&key) {
                entry.last_used.store(
                    self.lru_timer.fetch_add(1, Ordering::Relaxed),
                    Ordering::Relaxed,
                );
                return Ok(Arc::clone(entry.value()));
            }
        }

        let mut map = self.map.write().await;
        if let Some(entry) = map.get(&key) {
            entry.last_used.store(
                self.lru_timer.fetch_add(1, Ordering::Relaxed),
                Ordering::Relaxed,
            );
            return Ok(Arc::clone(entry.value()));
        }

        self.ensure_free_entry(&mut map).await?;

        let object = Arc::new(self.backend.load(key).await?);

        let new_entry = AsyncLruCacheEntry {
            value: Some(Arc::clone(&object)),
            last_used: AtomicUsize::new(self.lru_timer.fetch_add(1, Ordering::Relaxed)),
        };
        map.insert(key, new_entry);

        Ok(object)
    }

    /// Force-insert the given object into the cache.
    ///
    /// If there is an existing object under that key, it is flushed first.
    async fn insert(&self, key: K, value: Arc<V>) -> io::Result<()> {
        let mut map = self.map.write().await;
        if let Some(entry) = map.get_mut(&key) {
            entry.last_used.store(
                self.lru_timer.fetch_add(1, Ordering::Relaxed),
                Ordering::Relaxed,
            );
            let mut dep_guard = self.flush_before.lock().await;
            Self::flush_dependencies(&mut dep_guard).await?;
            self.backend.flush(key, Arc::clone(entry.value())).await?;
            entry.value = Some(value);
        } else {
            self.ensure_free_entry(&mut map).await?;

            let new_entry = AsyncLruCacheEntry {
                value: Some(value),
                last_used: AtomicUsize::new(self.lru_timer.fetch_add(1, Ordering::Relaxed)),
            };
            map.insert(key, new_entry);
        }

        Ok(())
    }

    /// Flush all cache entries.
    ///
    /// Those entries are not evicted, but remain in the cache.
    async fn flush(&self) -> io::Result<()> {
        let _span = span!(
            Level::TRACE,
            "AsyncLruCache::flush",
            self = &self as *const _ as usize
        )
        .entered();

        let mut futs = FutureVector::new();

        let mut dep_guard = self.flush_before.lock().await;
        Self::flush_dependencies(&mut dep_guard).await?;

        let map = self.map.read().await;
        for (key, entry) in map.iter() {
            let key = *key;
            let object = Arc::clone(entry.value());
            trace!("Flushing {key:?}");
            futs.push(Box::pin(self.backend.flush(key, object)));
        }

        futs.discarding_join().await
    }
}

impl<V> AsyncLruCacheEntry<V> {
    /// Return the cached object.
    fn value(&self) -> &Arc<V> {
        self.value.as_ref().unwrap()
    }
}

#[async_trait(?Send)]
impl<
        K: Clone + Copy + Debug + PartialEq + Eq + Hash + Send + Sync,
        V: Send + Sync,
        B: AsyncLruCacheBackend<Key = K, Value = V>,
    > FlushableCache for AsyncLruCacheInner<K, V, B>
{
    async fn flush(&self) -> io::Result<()> {
        AsyncLruCacheInner::<K, V, B>::flush(self).await
    }

    async fn check_circular(&self, other: &Arc<dyn FlushableCache>) -> bool {
        let deps = self.flush_before.lock().await;
        for dep in deps.iter() {
            if Arc::ptr_eq(dep, other) {
                return true;
            }
        }
        false
    }
}

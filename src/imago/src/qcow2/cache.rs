//! Provides functionality for the L2 and refblock caches.

use super::*;
use crate::async_lru_cache::AsyncLruCacheBackend;
use tracing::trace;

/// I/O back-end for the L2 table cache.
pub(super) struct L2CacheBackend<S: Storage> {
    /// Qcow2 metadata file.
    file: Arc<S>,

    /// Qcow2 header.
    header: Arc<Header>,
}

/// I/O back-end for the refblock cache.
pub(super) struct RefBlockCacheBackend<S: Storage> {
    /// Qcow2 metadata file.
    file: Arc<S>,

    /// Qcow2 header.
    header: Arc<Header>,
}

impl<S: Storage> L2CacheBackend<S> {
    /// Create a new `L2CacheBackend`.
    ///
    /// `file` is the qcow2 metadata (image) file.
    pub fn new(file: Arc<S>, header: Arc<Header>) -> Self {
        L2CacheBackend { file, header }
    }
}

impl<S: Storage> AsyncLruCacheBackend for L2CacheBackend<S> {
    type Key = HostCluster;
    type Value = L2Table;

    async fn load(&self, l2_cluster: HostCluster) -> io::Result<L2Table> {
        trace!("Loading L2 table");

        L2Table::load(
            self.file.as_ref(),
            &self.header,
            l2_cluster,
            self.header.l2_entries(),
        )
        .await
    }

    async fn flush(&self, l2_cluster: HostCluster, l2_table: Arc<L2Table>) -> io::Result<()> {
        trace!("Flushing L2 table");
        if l2_table.is_modified() {
            assert!(l2_table.get_cluster().unwrap() == l2_cluster);
            l2_table.write(self.file.as_ref()).await?;
        }
        Ok(())
    }
}

impl<S: Storage> RefBlockCacheBackend<S> {
    /// Create a new `RefBlockCacheBackend`.
    ///
    /// `file` is the qcow2 metadata (image) file.
    pub fn new(file: Arc<S>, header: Arc<Header>) -> Self {
        RefBlockCacheBackend { file, header }
    }
}

impl<S: Storage> AsyncLruCacheBackend for RefBlockCacheBackend<S> {
    type Key = HostCluster;
    type Value = RefBlock;

    async fn load(&self, rb_cluster: HostCluster) -> io::Result<RefBlock> {
        RefBlock::load(self.file.as_ref(), &self.header, rb_cluster).await
    }

    async fn flush(&self, rb_cluster: HostCluster, refblock: Arc<RefBlock>) -> io::Result<()> {
        if refblock.is_modified() {
            assert!(refblock.get_cluster().unwrap() == rb_cluster);
            refblock.write(self.file.as_ref()).await?;
        }
        Ok(())
    }
}

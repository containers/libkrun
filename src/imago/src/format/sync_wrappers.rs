//! Synchronous wrapper around [`FormatAccess`].

use super::drivers::FormatDriverInstance;
use crate::io_buffers::{IoVector, IoVectorMut};
use crate::{FormatAccess, Mapping, Storage};
use std::io;

/// Synchronous wrapper around [`FormatAccess`].
///
/// Creates and keeps a tokio runtime in which to run I/O.
pub struct SyncFormatAccess<S: Storage> {
    /// Wrapped asynchronous [`FormatAccess`].
    inner: FormatAccess<S>,

    /// Tokio runtime in which I/O is run.
    runtime: tokio::runtime::Runtime,
}

impl<S: Storage> SyncFormatAccess<S> {
    /// Like [`FormatAccess::new()`], but create a synchronous wrapper.
    pub fn new<D: FormatDriverInstance<Storage = S> + 'static>(inner: D) -> io::Result<Self> {
        FormatAccess::new(inner).try_into()
    }

    /// Get a reference to the contained async [`FormatAccess`] object.
    pub fn inner(&self) -> &FormatAccess<S> {
        &self.inner
    }

    /// Return the disk size in bytes.
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    /// Set the number of simultaneous async requests per read.
    ///
    /// When issuing read requests, issue this many async requests in parallel (still in a single
    /// thread).  The default count is `1`, i.e. no parallel requests.
    ///
    /// Note that inside of this synchronous wrapper, we still run async functions, so this setting
    /// is valid even for [`SyncFormatAccess`].
    pub fn set_async_read_parallelization(&mut self, count: usize) {
        self.inner.set_async_read_parallelization(count)
    }

    /// Set the number of simultaneous async requests per write.
    ///
    /// When issuing write requests, issue this many async requests in parallel (still in a single
    /// thread).  The default count is `1`, i.e. no parallel requests.
    ///
    /// Note that inside of this synchronous wrapper, we still run async functions, so this setting
    /// is valid even for [`SyncFormatAccess`].
    pub fn set_async_write_parallelization(&mut self, count: usize) {
        self.inner.set_async_write_parallelization(count)
    }

    /// Minimal I/O alignment, for both length and offset.
    ///
    /// All requests to this image should be aligned to this value, both in length and offset.
    ///
    /// Requests that do not match this alignment will be realigned internally, which requires
    /// creating bounce buffers and read-modify-write cycles for write requests, which is costly,
    /// so should be avoided.
    pub fn req_align(&self) -> usize {
        self.inner.req_align()
    }

    /// Minimal memory buffer alignment, for both address and length.
    ///
    /// All buffers used in requests to this image should be aligned to this value, both their
    /// address and length.
    ///
    /// Request buffers that do not match this alignment will be realigned internally, which
    /// requires creating bounce buffers, which is costly, so should be avoided.
    pub fn mem_align(&self) -> usize {
        self.inner.mem_align()
    }

    /// Return the mapping at `offset`.
    ///
    /// Find what `offset` is mapped to, return that mapping information, and the length of that
    /// continuous mapping (from `offset`).
    pub fn get_mapping_sync(
        &self,
        offset: u64,
        max_length: u64,
    ) -> io::Result<(Mapping<'_, S>, u64)> {
        self.runtime
            .block_on(self.inner.get_mapping(offset, max_length))
    }

    /// Create a raw data mapping at `offset`.
    ///
    /// Ensure that `offset` is directly mapped to some storage object, up to a length of `length`.
    /// Return the storage object, the corresponding offset there, and the continuous length that
    /// we were able to map (less than or equal to `length`).
    ///
    /// If `overwrite` is true, the contents in the range are supposed to be overwritten and may be
    /// discarded.  Otherwise, they are kept.
    pub fn ensure_data_mapping(
        &self,
        offset: u64,
        length: u64,
        overwrite: bool,
    ) -> io::Result<(&S, u64, u64)> {
        self.runtime
            .block_on(self.inner.ensure_data_mapping(offset, length, overwrite))
    }

    /// Read data at `offset` into `bufv`.
    ///
    /// Reads until `bufv` is filled completely, i.e. will not do short reads.  When reaching the
    /// end of file, the rest of `bufv` is filled with 0.
    pub fn readv(&self, bufv: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        self.runtime.block_on(self.inner.readv(bufv, offset))
    }

    /// Read data at `offset` into `buf`.
    ///
    /// Reads until `buf` is filled completely, i.e. will not do short reads.  When reaching the
    /// end of file, the rest of `buf` is filled with 0.
    pub fn read<'a>(&'a self, buf: impl Into<IoVectorMut<'a>>, offset: u64) -> io::Result<()> {
        self.readv(buf.into(), offset)
    }

    /// Write data from `bufv` to `offset`.
    ///
    /// Writes all data from `bufv` (or returns an error), i.e. will not do short writes.  Reaching
    /// the end of file before the end of the buffer results in an error.
    pub fn writev(&self, bufv: IoVector<'_>, offset: u64) -> io::Result<()> {
        self.runtime.block_on(self.inner.writev(bufv, offset))
    }

    /// Write data from `buf` to `offset`.
    ///
    /// Writes all data from `bufv` (or returns an error), i.e. will not do short writes.  Reaching
    /// the end of file before the end of the buffer results in an error.
    pub fn write<'a>(&'a self, buf: impl Into<IoVector<'a>>, offset: u64) -> io::Result<()> {
        self.writev(buf.into(), offset)
    }

    /// Flush internal buffers.
    ///
    /// Does not necessarily sync those buffers to disk.  When using `flush()`, consider whether
    /// you want to call `sync()` afterwards.
    pub fn flush(&self) -> io::Result<()> {
        self.runtime.block_on(self.inner.flush())
    }

    /// Sync data already written to the storage hardware.
    ///
    /// This does not necessarily include flushing internal buffers, i.e. `flush`.  When using
    /// `sync()`, consider whether you want to call `flush()` before it.
    pub fn sync(&self) -> io::Result<()> {
        self.runtime.block_on(self.inner.sync())
    }
}

impl<S: Storage> TryFrom<FormatAccess<S>> for SyncFormatAccess<S> {
    type Error = io::Error;

    fn try_from(async_access: FormatAccess<S>) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|err| {
                io::Error::other(format!(
                    "Failed to create a tokio runtime for synchronous image access: {err}"
                ))
            })?;

        Ok(SyncFormatAccess {
            inner: async_access,
            runtime,
        })
    }
}

// #[cfg(not(feature = "async-drop"))]
impl<S: Storage> Drop for SyncFormatAccess<S> {
    fn drop(&mut self) {
        if let Err(err) = self.flush() {
            let inner = &self.inner;
            tracing::error!("Failed to flush {inner}: {err}");
        }
    }
}

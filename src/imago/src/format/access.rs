//! Actual public image access functionality.
//!
//! Provides access to different image formats via `FormatAccess` objects.

use super::drivers::{self, FormatDriverInstance};
use crate::io_buffers::{IoVector, IoVectorMut};
use crate::vector_select::FutureVector;
use crate::{Storage, StorageExt};
use std::fmt::{self, Display, Formatter};
use std::{cmp, io, ptr};

/// Provides access to a disk image.
#[derive(Debug)]
pub struct FormatAccess<S: Storage> {
    /// Image format driver.
    inner: Box<dyn FormatDriverInstance<Storage = S>>,

    /// Whether this image may be modified.
    writable: bool,

    /// How many asynchronous requests to perform per read request in parallel.
    read_parallelization: usize,

    /// How many asynchronous requests to perform per write request in parallel.
    write_parallelization: usize,
}

/// Fully recursive mapping information.
///
/// Mapping information that resolves down to the storage object layer (except for special data).
#[derive(Debug)]
pub enum Mapping<'a, S: Storage> {
    /// Raw data.
    Raw {
        /// Storage object where this data is stored.
        storage: &'a S,

        /// Offset in `storage` where this data is stored.
        offset: u64,

        /// Whether this mapping may be written to.
        ///
        /// If `true`, you can directly write to `offset` on `storage` to change the disk image’s
        /// data accordingly.
        ///
        /// If `false`, the disk image format does not allow writing to `offset` on `storage`; a
        /// new mapping must be allocated first.
        writable: bool,
    },

    /// Range is to be read as zeroes.
    Zero,

    /// End of file reached.
    ///
    /// The accompanying length is always 0.
    Eof,

    /// Data is encoded in some manner, e.g. compressed or encrypted.
    ///
    /// Such data cannot be accessed directly, but must be interpreted by the image format driver.
    Special {
        /// Format layer where this special data was encountered.
        layer: &'a FormatAccess<S>,

        /// Original (“guest”) offset on `layer` to pass to `readv_special()`.
        offset: u64,
    },
}

// When adding new public methods, don’t forget to add them to sync_wrappers, too.
impl<S: Storage> FormatAccess<S> {
    /// Wrap a format driver instance in `FormatAccess`.
    ///
    /// `FormatAccess` provides I/O access to disk images, based on the functionality offered by
    /// the individual format drivers via `FormatDriverInstance`.
    pub fn new<D: FormatDriverInstance<Storage = S> + 'static>(inner: D) -> Self {
        let writable = inner.writable();
        FormatAccess {
            inner: Box::new(inner),
            read_parallelization: 1,
            write_parallelization: 1,
            writable,
        }
    }

    /// Return the disk size in bytes.
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    /// Set the number of simultaneous async requests per read.
    ///
    /// When issuing read requests, issue this many async requests in parallel (still in a single
    /// thread).  The default count is `1`, i.e. no parallel requests.
    pub fn set_async_read_parallelization(&mut self, count: usize) {
        self.read_parallelization = count;
    }

    /// Set the number of simultaneous async requests per write.
    ///
    /// When issuing write requests, issue this many async requests in parallel (still in a single
    /// thread).  The default count is `1`, i.e. no parallel requests.
    pub fn set_async_write_parallelization(&mut self, count: usize) {
        self.write_parallelization = count;
    }

    /// Return all storage dependencies of this image.
    ///
    /// Includes recursive dependencies, i.e. those from other image dependencies like backing
    /// images.
    pub(crate) fn collect_storage_dependencies(&self) -> Vec<&S> {
        self.inner.collect_storage_dependencies()
    }

    /// Minimal I/O alignment, for both length and offset.
    ///
    /// All requests to this image should be aligned to this value, both in length and offset.
    ///
    /// Requests that do not match this alignment will be realigned internally, which requires
    /// creating bounce buffers and read-modify-write cycles for write requests, which is costly,
    /// so should be avoided.
    pub fn req_align(&self) -> usize {
        self.inner
            .collect_storage_dependencies()
            .into_iter()
            .fold(1, |max, s| cmp::max(max, s.req_align()))
    }

    /// Minimal memory buffer alignment, for both address and length.
    ///
    /// All buffers used in requests to this image should be aligned to this value, both their
    /// address and length.
    ///
    /// Request buffers that do not match this alignment will be realigned internally, which
    /// requires creating bounce buffers, which is costly, so should be avoided.
    pub fn mem_align(&self) -> usize {
        self.inner
            .collect_storage_dependencies()
            .into_iter()
            .fold(1, |max, s| cmp::max(max, s.mem_align()))
    }

    /// Read the data from the given mapping.
    async fn read_chunk(
        &self,
        mut bufv: IoVectorMut<'_>,
        mapping: Mapping<'_, S>,
    ) -> io::Result<()> {
        match mapping {
            Mapping::Raw {
                storage,
                offset,
                writable: _,
            } => storage.readv(bufv, offset).await,

            Mapping::Zero | Mapping::Eof => {
                bufv.fill(0);
                Ok(())
            }

            // FIXME: TOCTTOU problem.  Not sure how to fully fix it, if possible at all.
            // (Concurrent writes can change the mapping, but the driver will have to reload the
            // mapping because it cannot pass it in `NonRecursiveMapping::Special`.  It may then
            // find that this is no longer a “special” range.  Even passing the low-level mapping
            // information in `Mapping::Special` wouldn’t fully fix it, though: If concurrent
            // writes change the low-level cluster type, and the driver then tries to e.g.
            // decompress the data that was there, that may well fail.)
            Mapping::Special { layer, offset } => layer.inner.readv_special(bufv, offset).await,
        }
    }

    /// Return the mapping at `offset`.
    ///
    /// Find what `offset` is mapped to, return that mapping information, and the length of that
    /// continuous mapping (from `offset`).
    pub async fn get_mapping(
        &self,
        mut offset: u64,
        mut max_length: u64,
    ) -> io::Result<(Mapping<'_, S>, u64)> {
        let mut format_layer = self;
        let mut writable_gate = true;

        loop {
            let (mapping, length) = format_layer.inner.get_mapping(offset, max_length).await?;
            let length = std::cmp::min(length, max_length);

            match mapping {
                drivers::Mapping::Raw {
                    storage,
                    offset,
                    writable,
                } => {
                    return Ok((
                        Mapping::Raw {
                            storage,
                            offset,
                            writable: writable && writable_gate,
                        },
                        length,
                    ))
                }

                drivers::Mapping::Indirect {
                    layer: recurse_layer,
                    offset: recurse_offset,
                    writable: recurse_writable,
                } => {
                    format_layer = recurse_layer;
                    offset = recurse_offset;
                    writable_gate = recurse_writable;
                    max_length = length;
                }

                drivers::Mapping::Zero => return Ok((Mapping::Zero, length)),

                drivers::Mapping::Eof => {
                    // Return EOF only on top layer, zero otherwise
                    return if ptr::eq(format_layer, self) {
                        Ok((Mapping::Eof, 0))
                    } else {
                        Ok((Mapping::Zero, max_length))
                    };
                }

                drivers::Mapping::Special { offset } => {
                    return Ok((
                        Mapping::Special {
                            layer: format_layer,
                            offset,
                        },
                        length,
                    ));
                }
            }
        }
    }

    /// Create a raw data mapping at `offset`.
    ///
    /// Ensure that `offset` is directly mapped to some storage object, up to a length of `length`.
    /// Return the storage object, the corresponding offset there, and the continuous length that
    /// we were able to map (less than or equal to `length`).
    ///
    /// If `overwrite` is true, the contents in the range are supposed to be overwritten and may be
    /// discarded.  Otherwise, they are kept.
    pub async fn ensure_data_mapping(
        &self,
        offset: u64,
        length: u64,
        overwrite: bool,
    ) -> io::Result<(&S, u64, u64)> {
        let (storage, mapped_offset, mapped_length) = self
            .inner
            .ensure_data_mapping(offset, length, overwrite)
            .await?;
        let mapped_length = cmp::min(length, mapped_length);
        assert!(mapped_length > 0);
        Ok((storage, mapped_offset, mapped_length))
    }

    /// Read data at `offset` into `bufv`.
    ///
    /// Reads until `bufv` is filled completely, i.e. will not do short reads.  When reaching the
    /// end of file, the rest of `bufv` is filled with 0.
    pub async fn readv(&self, mut bufv: IoVectorMut<'_>, mut offset: u64) -> io::Result<()> {
        let mut workers = (self.read_parallelization > 1).then(FutureVector::new);

        while !bufv.is_empty() {
            let (mapping, chunk_length) = self.get_mapping(offset, bufv.len()).await?;
            if chunk_length == 0 {
                assert!(mapping.is_eof());
                bufv.fill(0);
                break;
            }

            if let Some(workers) = workers.as_mut() {
                while workers.len() >= self.read_parallelization {
                    workers.select().await?;
                }
            }

            let (chunk, remainder) = bufv.split_at(chunk_length);
            bufv = remainder;
            offset += chunk_length;

            if let Some(workers) = workers.as_mut() {
                workers.push(Box::pin(self.read_chunk(chunk, mapping)));
            } else {
                self.read_chunk(chunk, mapping).await?;
            }
        }

        if let Some(mut workers) = workers {
            workers.discarding_join().await?;
        }

        Ok(())
    }

    /// Read data at `offset` into `buf`.
    ///
    /// Reads until `buf` is filled completely, i.e. will not do short reads.  When reaching the
    /// end of file, the rest of `buf` is filled with 0.
    pub async fn read(&self, buf: impl Into<IoVectorMut<'_>>, offset: u64) -> io::Result<()> {
        self.readv(buf.into(), offset).await
    }

    /// Write data from `bufv` to `offset`.
    ///
    /// Writes all data from `bufv` (or returns an error), i.e. will not do short writes.  Reaching
    /// the end of file before the end of the buffer results in an error.
    pub async fn writev(&self, mut bufv: IoVector<'_>, mut offset: u64) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::other("Image is read-only"));
        }

        // Limit to disk size
        let disk_size = self.inner.size();
        if offset >= disk_size {
            return Ok(());
        }
        if bufv.len() > disk_size - offset {
            bufv = bufv.split_at(disk_size - offset).0;
        }

        let mut workers = (self.write_parallelization > 1).then(FutureVector::new);

        while !bufv.is_empty() {
            let (storage, st_offset, st_length) =
                self.ensure_data_mapping(offset, bufv.len(), true).await?;

            if let Some(workers) = workers.as_mut() {
                while workers.len() >= self.write_parallelization {
                    workers.select().await?;
                }
            }

            let (chunk, remainder) = bufv.split_at(st_length);
            bufv = remainder;
            offset += st_length;

            if let Some(workers) = workers.as_mut() {
                workers.push(Box::pin(storage.writev(chunk, st_offset)));
            } else {
                storage.writev(chunk, st_offset).await?;
            }
        }

        if let Some(mut workers) = workers {
            workers.discarding_join().await?;
        }

        Ok(())
    }

    /// Write data from `buf` to `offset`.
    ///
    /// Writes all data from `bufv` (or returns an error), i.e. will not do short writes.  Reaching
    /// the end of file before the end of the buffer results in an error.
    pub async fn write(&self, buf: impl Into<IoVector<'_>>, offset: u64) -> io::Result<()> {
        self.writev(buf.into(), offset).await
    }

    /// Flush internal buffers.  Always call this before drop!
    ///
    /// Does not necessarily sync those buffers to disk.  When using `flush()`, consider whether
    /// you want to call `sync()` afterwards.
    ///
    /// Because of the current lack of stable `async_drop`, you must manually call this before
    /// dropping a `FormatAccess` instance!  (Not necessarily for read-only images, though.)
    #[allow(async_fn_in_trait)] // No need for Send
    pub async fn flush(&self) -> io::Result<()> {
        self.inner.flush().await
    }

    /// Sync data already written to the storage hardware.
    ///
    /// This does not necessarily include flushing internal buffers, i.e. `flush`.  When using
    /// `sync()`, consider whether you want to call `flush()` before it.
    #[allow(async_fn_in_trait)] // No need for Send
    pub async fn sync(&self) -> io::Result<()> {
        self.inner.sync().await
    }
}

impl<S: Storage> Mapping<'_, S> {
    /// Return `true` if and only if this mapping signifies the end of file.
    pub fn is_eof(&self) -> bool {
        matches!(self, Mapping::Eof)
    }
}

impl<S: Storage> Display for FormatAccess<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<S: Storage> Display for Mapping<'_, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Mapping::Raw {
                storage,
                offset,
                writable,
            } => {
                let writable = if *writable { "rw" } else { "ro" };
                write!(f, "{storage}:0x{offset:x}/{writable}")
            }

            Mapping::Zero => write!(f, "<zero>"),

            Mapping::Eof => write!(f, "<eof>"),

            Mapping::Special { layer, offset } => {
                write!(f, "<special:{layer}:0x{offset:x}>")
            }
        }
    }
}

/*
#[cfg(feature = "async-drop")]
impl<S: Storage> std::future::AsyncDrop for FormatAccess<S> {
    type Dropper<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> where S: 'a;

    fn async_drop(self: std::pin::Pin<&mut Self>) -> Self::Dropper<'_> {
        Box::pin(async move {
            if let Err(err) = self.flush().await {
                let inner = &self.inner;
                tracing::error!("Failed to flush {inner}: {err}");
            }
        })
    }
}
*/

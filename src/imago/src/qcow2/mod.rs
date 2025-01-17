//! Qcow2 implementation.

mod allocation;
mod cache;
mod compressed;
mod cow;
mod io_func;
mod mappings;
mod metadata;
#[cfg(feature = "sync-wrappers")]
mod sync_wrappers;
mod types;

use crate::async_lru_cache::AsyncLruCache;
use crate::format::drivers::{FormatDriverInstance, Mapping};
use crate::format::wrapped::WrappedFormat;
use crate::io_buffers::IoVectorMut;
use crate::misc_helpers::{invalid_data, ResultErrorContext};
use crate::raw::Raw;
use crate::{FormatAccess, Storage, StorageExt, StorageOpenOptions};
use allocation::Allocator;
use async_trait::async_trait;
use cache::L2CacheBackend;
use metadata::*;
use std::fmt::{self, Debug, Display, Formatter};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::{cmp, io};
use tokio::sync::{Mutex, RwLock};
use types::*;

/// Access qcow2 images.
///
/// Allows access to qcow2 images (v2 and v3), referencing the following objects:
/// - Metadata storage object: The image file itself
/// - Data file (storage object): May be the image file itself, or an external data file
/// - Backing image `WrappedFormat<S>`: A backing disk image in any format
#[must_use = "qcow2 images must be flushed before closing"]
pub struct Qcow2<S: Storage + 'static, F: WrappedFormat<S> + 'static = FormatAccess<S>> {
    /// Image file (which contains the qcow2 metadata).
    metadata: Arc<S>,

    /// Whether this image may be modified.
    writable: bool,

    /// Whether the user explicitly assigned a data file storage object (or `None`).
    storage_set: bool,
    /// Data file storage object; will use `metadata` if `None`.
    storage: Option<S>,
    /// Whether the user explicitly assigned a backing file (or `None`).
    backing_set: bool,
    /// Backing image.
    backing: Option<F>,

    /// Qcow2 header.
    header: Arc<Header>,
    /// L1 table.
    l1_table: RwLock<L1Table>,

    /// L2 table cache.
    l2_cache: AsyncLruCache<HostCluster, L2Table, L2CacheBackend<S>>,

    /// Allocates clusters.
    ///
    /// Is `None` for read-only images.
    allocator: Option<Mutex<Allocator<S>>>,
}

impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> Qcow2<S, F> {
    /// Opens a qcow2 file.
    ///
    /// `metadata` is the file containing the qcow2 metadata.  If `writable` is not set, no
    /// modifications are permitted.
    ///
    /// This will not open any other storage objects needed, i.e. no backing image, no external
    /// data file.  If you want to handle those manually, check whether an external data file is
    /// needed via [`Qcow2::requires_external_data_file()`], and, if necessary, assign one via
    /// [`Qcow2::set_data_file()`]; and assign a backing image via [`Qcow2::set_backing()`].
    ///
    /// If you want to use the implicit references given in the image header, use
    /// [`Qcow2::open_implicit_dependencies()`].
    pub async fn open_image(metadata: S, writable: bool) -> io::Result<Self> {
        let header = Arc::new(Header::load(&metadata, writable).await?);

        let cb = header.cluster_bits();
        let l1_offset = header.l1_table_offset();
        let l1_cluster = l1_offset
            .checked_cluster(cb)
            .ok_or_else(|| invalid_data("Unaligned L1 table: {l1_offset}"))?;

        let l1_table =
            L1Table::load(&metadata, &header, l1_cluster, header.l1_table_entries()).await?;

        let metadata = Arc::new(metadata);

        let allocator = if writable {
            let allocator = Allocator::new(Arc::clone(&metadata), Arc::clone(&header)).await?;
            Some(Mutex::new(allocator))
        } else {
            None
        };

        let l2_cache_backend = L2CacheBackend::new(Arc::clone(&metadata), Arc::clone(&header));
        let l2_cache = AsyncLruCache::new(l2_cache_backend, 128);

        Ok(Qcow2 {
            metadata,

            writable,

            storage_set: false,
            storage: None,
            backing_set: false,
            backing: None,

            header,
            l1_table: RwLock::new(l1_table),

            l2_cache,
            allocator,
        })
    }

    /// Open a qcow2 file at the given path.
    ///
    /// Open the file as a storage object via [`Storage::open()`], with write access if specified,
    /// then pass that object to [`Qcow2::open_image()`].
    ///
    /// This will not open any other storage objects needed, i.e. no backing image, no external
    /// data file.  If you want to handle those manually, check whether an external data file is
    /// needed via [`Qcow2::requires_external_data_file()`], and, if necessary, assign one via
    /// [`Qcow2::set_data_file()`]; and assign a backing image via [`Qcow2::set_backing()`].
    ///
    /// If you want to use the implicit references given in the image header, use
    /// [`Qcow2::open_implicit_dependencies()`].
    pub async fn open_path<P: AsRef<Path>>(path: P, writable: bool) -> io::Result<Self> {
        let storage_opts = StorageOpenOptions::new().write(writable).filename(path);
        let metadata = S::open(storage_opts).await?;
        Self::open_image(metadata, writable).await
    }

    /// Check whether the given image file is a qcow2 file.
    pub(crate) async fn probe(metadata: &S) -> io::Result<()> {
        Header::load(metadata, true).await?;
        Ok(())
    }

    /// Does this qcow2 image require an external data file?
    ///
    /// Conversely, if this is `false`, this image must not use an external data file.
    pub fn requires_external_data_file(&self) -> bool {
        self.header.external_data_file()
    }

    /// External data file filename given in the image header.
    ///
    /// Note that even if an image requires an external data file, the header may not contain its
    /// filename.  In this case, an external data file must be set explicitly via
    /// [`Qcow2::set_data_file()`].
    pub fn implicit_external_data_file(&self) -> Option<&String> {
        self.header.external_data_filename()
    }

    /// Backing image filename given in the image header.
    pub fn implicit_backing_file(&self) -> Option<&String> {
        self.header.backing_filename()
    }

    /// Backing image format given in the image header.
    ///
    /// If this is `None`, the backing image’s format should be probed.  Note that this may be
    /// dangerous if guests have write access to the backing file: Given a raw image, a guest can
    /// write a qcow2 header into it, resulting in the image being opened as qcow2 the next time,
    /// allowing the guest to read arbitrary files (e.g. by setting them as backing files).
    pub fn implicit_backing_format(&self) -> Option<&String> {
        self.header.backing_format()
    }

    /// Assign the data file.
    ///
    /// `None` means using the same data storage for both metadata and data, which should be used
    /// if [`Qcow2::requires_external_data_file()`] is `false`.
    pub fn set_data_file(&mut self, file: Option<S>) {
        self.storage = file;
        self.storage_set = true;
    }

    /// Assign a backing image.
    ///
    /// `None` means no backing image, i.e. reading from unallocated areas will produce zeroes.
    pub fn set_backing(&mut self, backing: Option<F>) {
        self.backing = backing;
        self.backing_set = true;
    }

    /// Get the data storage object.
    ///
    /// If we have an external data file, return that.  Otherwise, return the image (metadata)
    /// file.
    fn storage(&self) -> &S {
        self.storage.as_ref().unwrap_or(&self.metadata)
    }

    /// Return the image’s implicit data file (as given in the image header).
    async fn open_implicit_data_file(&self) -> io::Result<Option<S>> {
        if !self.header.external_data_file() {
            return Ok(None);
        }

        let Some(filename) = self.header.external_data_filename() else {
            return Err(io::Error::other(
                "Image requires external data file, but no filename given",
            ));
        };

        let absolute = self
            .metadata
            .resolve_relative_path(filename)
            .err_context(|| format!("Cannot resolve external data file name {filename}"))?;

        let opts = StorageOpenOptions::new()
            .write(true)
            .filename(absolute.clone());

        Ok(Some(S::open(opts).await.err_context(|| {
            format!("External data file {absolute:?}")
        })?))
    }

    /// Wrap `file` in the `Raw` format.  Helper for [`Qcow2::implicit_backing_file()`].
    async fn open_raw_backing_file(&self, file: S) -> io::Result<F> {
        let raw = Raw::open_image(file, false).await?;
        Ok(F::wrap(FormatAccess::new(raw)))
    }

    /// Wrap `file` in the `Qcow2` format.  Helper for [`Qcow2::implicit_backing_file()`].
    async fn open_qcow2_backing_file(&self, file: S) -> io::Result<F> {
        let mut qcow2 = Self::open_image(file, false).await?;
        // Recursive, so needs to be boxed
        Box::pin(qcow2.open_implicit_dependencies()).await?;
        Ok(F::wrap(FormatAccess::new(qcow2)))
    }

    /// Return the image’s implicit backing image (as given in the image header).
    async fn open_implicit_backing_file(&self) -> io::Result<Option<F>> {
        let Some(filename) = self.header.backing_filename() else {
            return Ok(None);
        };

        let absolute = self
            .metadata
            .resolve_relative_path(filename)
            .err_context(|| format!("Cannot resolve backing file name {filename}"))?;

        let opts = StorageOpenOptions::new().filename(absolute.clone());
        let file = S::open(opts)
            .await
            .err_context(|| format!("Backing file {absolute:?}"))?;

        let result = match self.header.backing_format().map(|f| f.as_str()) {
            Some("qcow2") => self.open_qcow2_backing_file(file).await.map(Some),
            Some("raw") | Some("file") => self.open_raw_backing_file(file).await.map(Some),

            Some(fmt) => Err(io::Error::other(format!("Unknown backing format {fmt}"))),

            None => {
                if Self::probe(&file).await.is_ok() {
                    self.open_qcow2_backing_file(file).await.map(Some)
                } else {
                    self.open_raw_backing_file(file).await.map(Some)
                }
            }
        };

        result.err_context(|| format!("Backing file {absolute:?}"))
    }

    /// Open all implicit dependencies.
    ///
    /// Qcow2 images have dependencies:
    /// - The metadata file, which is the image file itself.
    /// - The data file, which may be the same as the metadata file, or may be an external data
    ///   file.
    /// - A backing disk image in any format.
    ///
    /// All of this can be set explicitly:
    /// - The metadata file is always given explicitly to [`Qcow2::open_image()`].
    /// - The data file can be set via [`Qcow2::set_data_file()`].
    /// - The backing image can be set via [`Qcow2::set_backing()`].
    ///
    /// But the image header can also provide “default” references to the data file and a backing
    /// image, which we call *implicit* dependencies.  This function opens all such implicit
    /// dependencies if they have not been overridden with prior calls to
    /// [`Qcow2::set_data_file()`] or [`Qcow2::set_backing()`], respectively.
    pub async fn open_implicit_dependencies(&mut self) -> io::Result<()> {
        if !self.storage_set {
            self.storage = self.open_implicit_data_file().await?;
            self.storage_set = true;
        }

        if !self.backing_set {
            self.backing = self.open_implicit_backing_file().await?;
            self.backing_set = true;
        }

        Ok(())
    }

    /// Require write access, i.e. return an error for read-only images.
    fn need_writable(&self) -> io::Result<()> {
        self.writable
            .then_some(())
            .ok_or_else(|| io::Error::other("Image is read-only"))
    }
}

#[async_trait(?Send)]
impl<S: Storage, F: WrappedFormat<S>> FormatDriverInstance for Qcow2<S, F> {
    type Storage = S;

    fn size(&self) -> u64 {
        self.header.size()
    }

    fn collect_storage_dependencies(&self) -> Vec<&S> {
        let mut v = self
            .backing
            .as_ref()
            .map(|b| b.unwrap().collect_storage_dependencies())
            .unwrap_or_default();

        v.push(&self.metadata);
        if let Some(storage) = self.storage.as_ref() {
            v.push(storage);
        }

        v
    }

    fn writable(&self) -> bool {
        self.writable
    }

    async fn get_mapping<'a>(
        &'a self,
        offset: u64,
        max_length: u64,
    ) -> io::Result<(Mapping<'a, S>, u64)> {
        let length_until_eof = match self.header.size().checked_sub(offset) {
            None | Some(0) => return Ok((Mapping::Eof, 0)),
            Some(length) => length,
        };

        let max_length = cmp::min(max_length, length_until_eof);
        let offset = GuestOffset(offset);
        self.do_get_mapping(offset, max_length).await
    }

    async fn ensure_data_mapping<'a>(
        &'a self,
        offset: u64,
        length: u64,
        overwrite: bool,
    ) -> io::Result<(&'a S, u64, u64)> {
        let length_until_eof = self.header.size().saturating_sub(offset);
        if length_until_eof < length {
            return Err(io::Error::other("Cannot allocate beyond the disk size"));
        }

        if length == 0 {
            return Ok((self.storage(), 0, 0));
        }

        self.need_writable()?;
        let offset = GuestOffset(offset);
        self.do_ensure_data_mapping(offset, length, overwrite).await
    }

    async fn readv_special(&self, bufv: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        let offset = GuestOffset(offset);
        self.do_readv_special(bufv, offset).await
    }

    async fn flush(&self) -> io::Result<()> {
        self.l2_cache.flush().await?;
        if let Some(allocator) = self.allocator.as_ref() {
            allocator.lock().await.flush_rb_cache().await?;
        }

        self.metadata.flush().await?;
        if let Some(storage) = self.storage.as_ref() {
            storage.flush().await?;
        }
        // Backing file is read-only, so need not be flushed from us.
        Ok(())
    }

    async fn sync(&self) -> io::Result<()> {
        self.metadata.sync().await?;
        if let Some(storage) = self.storage.as_ref() {
            storage.sync().await?;
        }
        // Backing file is read-only, so need not be synced from us.
        Ok(())
    }
}

impl<S: Storage + 'static, F: WrappedFormat<S>> Debug for Qcow2<S, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Qcow2")
            .field("metadata", &self.metadata)
            .field("storage_set", &self.storage_set)
            .field("storage", &self.storage)
            .field("backing_set", &self.backing_set)
            .field("backing", &self.backing)
            .finish()
    }
}

impl<S: Storage + 'static, F: WrappedFormat<S>> Display for Qcow2<S, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "qcow2[{}]", self.metadata)
    }
}

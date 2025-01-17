//! Helper functionality to access storage.
//!
//! While not the primary purpose of this crate, to open VM images, we need to be able to access
//! different kinds of storage objects.  Such objects are abstracted behind the `Storage` trait.

pub(crate) mod drivers;
pub mod ext;

use crate::io_buffers::{IoBuffer, IoVector, IoVectorMut};
use drivers::CommonStorageHelper;
use ext::StorageExt;
use std::fmt::{Debug, Display};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::{cmp, io};

/// Parameters from which a storage object can be constructed.
#[derive(Clone, Default)]
pub struct StorageOpenOptions {
    /// Filename to open.
    pub(crate) filename: Option<PathBuf>,

    /// Whether the object should be opened as writable or read-only.
    pub(crate) writable: bool,

    /// Whether to bypass the host page cache (if applicable).
    pub(crate) direct: bool,
}

/// Implementation for storage objects.
pub trait Storage: Debug + Display + Send + Sized + Sync {
    /// Open a storage object.
    ///
    /// Different storage implementations may require different options.
    #[allow(async_fn_in_trait)] // No need for Send
    async fn open(_opts: StorageOpenOptions) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Cannot open storage objects of type {}",
                std::any::type_name::<Self>()
            ),
        ))
    }

    /// Synchronous wrapper around [`Storage::open()`].
    #[cfg(feature = "sync-wrappers")]
    fn open_sync(opts: StorageOpenOptions) -> io::Result<Self> {
        tokio::runtime::Builder::new_current_thread()
            .build()?
            .block_on(Self::open(opts))
    }

    /// Minimum required alignment for memory buffers.
    fn mem_align(&self) -> usize {
        1
    }

    /// Minimum required alignment for offsets and lengths.
    fn req_align(&self) -> usize {
        1
    }

    /// Minimum required alignment for zero writes.
    fn zero_align(&self) -> usize {
        1
    }

    /// Minimum required alignment for effective discards.
    fn discard_align(&self) -> usize {
        1
    }

    /// Storage object length.
    fn size(&self) -> io::Result<u64>;

    /// Resolve the given path relative to this storage object.
    ///
    /// `relative` need not really be a relative path; it is up to the storage driver to check
    /// whether it is an absolute path that does not need to be changed, or a relative path that
    /// needs to be resolved.
    ///
    /// Must not return a relative path.
    ///
    /// The returned `PathBuf` should be usable with `StorageOpenOptions::filename()`.
    fn resolve_relative_path<P: AsRef<Path>>(&self, _relative: P) -> io::Result<PathBuf> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Read data at `offset` into `bufv`.
    ///
    /// Reads until `bufv` is filled completely, i.e. will not do short reads.  When reaching the
    /// end of file, the rest of `bufv` is filled with 0.
    ///
    /// # Safety
    /// This is a pure read from storage.  The request must be fully aligned to
    /// [`Self::mem_align()`] and [`Self::req_align()`], and safeguards we want to implement for
    /// safe concurrent access may not be available.
    ///
    /// Use [`StorageExt::readv()`] instead.
    #[allow(async_fn_in_trait)] // No need for Send
    async unsafe fn pure_readv(&self, bufv: IoVectorMut<'_>, offset: u64) -> io::Result<()>;

    /// Write data from `bufv` to `offset`.
    ///
    /// Writes all data from `bufv`, i.e. will not do short writes.  When reaching the end of file,
    /// grow it as necessary so that the new end of file will be at `offset + bufv.len()`.
    ///
    /// If growing is not possible, writes beyond the end of file (even if only partially) should
    /// fail.
    ///
    /// # Safety
    /// This is a pure write to storage.  The request must be fully aligned to
    /// [`Self::mem_align()`] and [`Self::req_align()`], and safeguards we want to implement for
    /// safe concurrent access may not be available.
    ///
    /// Use [`StorageExt::writev()`] instead.
    #[allow(async_fn_in_trait)] // No need for Send
    async unsafe fn pure_writev(&self, bufv: IoVector<'_>, offset: u64) -> io::Result<()>;

    /// Ensure the given range reads back as zeroes.
    ///
    /// The default implementation writes actual zeroes as data, which is inefficient.  Storage
    /// drivers should override it with a more efficient implementation.
    ///
    /// # Safety
    /// This is a pure write to storage.  The request must be fully aligned to
    /// [`Self::zero_align()`], and safeguards we want to implement for safe concurrent access may
    /// not be available.
    ///
    /// Use [`StorageExt::write_zeroes()`] instead.
    #[allow(async_fn_in_trait)] // No need for Send
    async unsafe fn pure_write_zeroes(&self, mut offset: u64, mut length: u64) -> io::Result<()> {
        let buflen = cmp::min(length, 1048576) as usize;
        let mut buf = IoBuffer::new(buflen, self.mem_align())?;
        buf.as_mut().into_slice().fill(0);

        while length > 0 {
            let chunk_length = cmp::min(length, 1048576) as usize;
            self.writev(buf.as_ref_range(0..chunk_length).into(), offset)
                .await?;
            offset += chunk_length as u64;
            length -= chunk_length as u64;
        }

        Ok(())
    }

    /// Discard the given range, with undefined contents when read back.
    ///
    /// Tell the storage layer this range is no longer needed and need not be backed by actual
    /// storage.  When read back, the data read will be undefined, i.e. not necessarily zeroes.
    ///
    /// No-op implementations therefore explicitly fulfill the interface contract.
    ///
    /// # Safety
    /// This is a pure write to storage.  The request must be fully aligned to
    /// [`Self::discard_align()`], and safeguards we want to implement for safe concurrent access
    /// may not be available.
    ///
    /// Use [`StorageExt::discard()`] instead.
    #[allow(async_fn_in_trait)] // No need for Send
    async unsafe fn pure_discard(&self, _offset: u64, _length: u64) -> io::Result<()> {
        Ok(())
    }

    /// Flush internal buffers.
    ///
    /// Does not necessarily sync those buffers to disk.  When using `flush()`, consider whether
    /// you want to call `sync()` afterwards.
    #[allow(async_fn_in_trait)] // No need for Send
    async fn flush(&self) -> io::Result<()>;

    /// Sync data already written to the storage hardware.
    ///
    /// This does not necessarily include flushing internal buffers, i.e. `flush`.  When using
    /// `sync()`, consider whether you want to call `flush()` before it.
    #[allow(async_fn_in_trait)] // No need for Send
    async fn sync(&self) -> io::Result<()>;

    /// Return the storage helper object (used by the [`StorageExt`] implementation).
    fn get_storage_helper(&self) -> &CommonStorageHelper;
}

/// Allow dynamic use of storage objects (i.e. is object safe).
///
/// When using normal `Storage` objects, they must all be of the same type within a single disk
/// image chain.  For example, every storage object underneath a `FormatAccess<StdFile>` object
/// must be of type `StdFile`.
///
/// `DynStorage` allows the use of `Box<dyn DynStorage>`, which implements `Storage`, to allow
/// mixed storage object types.  Therefore, a `FormatAccess<Box<dyn DynStorage>>` allows e.g. the
/// use of both `Box<StdFile>` and `Box<Null>` storage objects together.  (`Arc` instead of `Box`
/// works, too.)
///
/// Async functions in `DynStorage` return boxed futures (`Pin<Box<dyn Future>>`), which makes them
/// slighly less efficient than async functions in `Storage`, hence the distinction.
pub trait DynStorage: Debug + Display + Send + Sync {
    /// Wrapper around [`Storage::mem_align()`].
    fn dyn_mem_align(&self) -> usize;

    /// Wrapper around [`Storage::req_align()`].
    fn dyn_req_align(&self) -> usize;

    /// Wrapper around [`Storage::zero_align()`].
    fn dyn_zero_align(&self) -> usize;

    /// Wrapper around [`Storage::discard_align()`].
    fn dyn_discard_align(&self) -> usize;

    /// Wrapper around [`Storage::size()`].
    fn dyn_size(&self) -> io::Result<u64>;

    /// Wrapper around [`Storage::resolve_relative_path()`].
    fn dyn_resolve_relative_path(&self, relative: &Path) -> io::Result<PathBuf>;

    /// Object-safe wrapper around [`Storage::pure_readv()`].
    ///
    /// # Safety
    /// Same considerations are for [`Storage::pure_readv()`] apply.
    unsafe fn dyn_pure_readv<'a>(
        &'a self,
        bufv: IoVectorMut<'a>,
        offset: u64,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>>;

    /// Object-safe wrapper around [`Storage::pure_writev()`].
    ///
    /// # Safety
    /// Same considerations are for [`Storage::pure_writev()`] apply.
    unsafe fn dyn_pure_writev<'a>(
        &'a self,
        bufv: IoVector<'a>,
        offset: u64,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>>;

    /// Object-safe wrapper around [`Storage::pure_write_zeroes()`].
    ///
    /// # Safety
    /// Same considerations are for [`Storage::pure_write_zeroes()`] apply.
    unsafe fn dyn_pure_write_zeroes(
        &self,
        offset: u64,
        length: u64,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_>>;

    /// Object-safe wrapper around [`Storage::pure_discard()`].
    ///
    /// # Safety
    /// Same considerations are for [`Storage::pure_discard()`] apply.
    unsafe fn dyn_pure_discard(
        &self,
        offset: u64,
        length: u64,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_>>;

    /// Object-safe wrapper around [`Storage::flush()`].
    fn dyn_flush(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_>>;

    /// Object-safe wrapper around [`Storage::sync()`].
    fn dyn_sync(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_>>;

    /// Wrapper around [`Storage::get_storage_helper()`].
    fn dyn_get_storage_helper(&self) -> &CommonStorageHelper;
}

impl<S: Storage> Storage for &S {
    fn mem_align(&self) -> usize {
        (*self).mem_align()
    }

    fn req_align(&self) -> usize {
        (*self).req_align()
    }

    fn zero_align(&self) -> usize {
        (*self).zero_align()
    }

    fn discard_align(&self) -> usize {
        (*self).discard_align()
    }

    fn size(&self) -> io::Result<u64> {
        (*self).size()
    }

    fn resolve_relative_path<P: AsRef<Path>>(&self, relative: P) -> io::Result<PathBuf> {
        (*self).resolve_relative_path(relative)
    }

    async unsafe fn pure_readv(&self, bufv: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        unsafe { (*self).pure_readv(bufv, offset).await }
    }

    async unsafe fn pure_writev(&self, bufv: IoVector<'_>, offset: u64) -> io::Result<()> {
        unsafe { (*self).pure_writev(bufv, offset).await }
    }

    async unsafe fn pure_write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        unsafe { (*self).pure_write_zeroes(offset, length).await }
    }

    async unsafe fn pure_discard(&self, offset: u64, length: u64) -> io::Result<()> {
        unsafe { (*self).pure_discard(offset, length).await }
    }

    async fn flush(&self) -> io::Result<()> {
        (*self).flush().await
    }

    async fn sync(&self) -> io::Result<()> {
        (*self).sync().await
    }

    fn get_storage_helper(&self) -> &CommonStorageHelper {
        (*self).get_storage_helper()
    }
}

impl<S: Storage> DynStorage for S {
    fn dyn_mem_align(&self) -> usize {
        <S as Storage>::mem_align(self)
    }

    fn dyn_req_align(&self) -> usize {
        <S as Storage>::req_align(self)
    }

    fn dyn_zero_align(&self) -> usize {
        <S as Storage>::zero_align(self)
    }

    fn dyn_discard_align(&self) -> usize {
        <S as Storage>::discard_align(self)
    }

    fn dyn_size(&self) -> io::Result<u64> {
        <S as Storage>::size(self)
    }

    fn dyn_resolve_relative_path(&self, relative: &Path) -> io::Result<PathBuf> {
        <S as Storage>::resolve_relative_path(self, relative)
    }

    unsafe fn dyn_pure_readv<'a>(
        &'a self,
        bufv: IoVectorMut<'a>,
        offset: u64,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>> {
        Box::pin(unsafe { <S as Storage>::pure_readv(self, bufv, offset) })
    }

    unsafe fn dyn_pure_writev<'a>(
        &'a self,
        bufv: IoVector<'a>,
        offset: u64,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>> {
        Box::pin(unsafe { <S as Storage>::pure_writev(self, bufv, offset) })
    }

    unsafe fn dyn_pure_write_zeroes(
        &self,
        offset: u64,
        length: u64,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_>> {
        Box::pin(unsafe { <S as Storage>::pure_write_zeroes(self, offset, length) })
    }

    unsafe fn dyn_pure_discard(
        &self,
        offset: u64,
        length: u64,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_>> {
        Box::pin(unsafe { <S as Storage>::pure_discard(self, offset, length) })
    }

    fn dyn_flush(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_>> {
        Box::pin(<S as Storage>::flush(self))
    }

    fn dyn_sync(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_>> {
        Box::pin(<S as Storage>::sync(self))
    }

    fn dyn_get_storage_helper(&self) -> &CommonStorageHelper {
        <S as Storage>::get_storage_helper(self)
    }
}

impl Storage for Box<dyn DynStorage> {
    async fn open(opts: StorageOpenOptions) -> io::Result<Self> {
        // TODO: When we have more drivers, choose different defaults depending on the options
        // given.  Right now, only `File` really supports being opened through options, so it is an
        // obvious choice.
        Ok(Box::new(crate::file::File::open(opts).await?))
    }

    fn mem_align(&self) -> usize {
        self.as_ref().dyn_mem_align()
    }

    fn req_align(&self) -> usize {
        self.as_ref().dyn_req_align()
    }

    fn zero_align(&self) -> usize {
        self.as_ref().dyn_zero_align()
    }

    fn discard_align(&self) -> usize {
        self.as_ref().dyn_discard_align()
    }

    fn size(&self) -> io::Result<u64> {
        self.as_ref().dyn_size()
    }

    fn resolve_relative_path<P: AsRef<Path>>(&self, relative: P) -> io::Result<PathBuf> {
        self.as_ref().dyn_resolve_relative_path(relative.as_ref())
    }

    async unsafe fn pure_readv(&self, bufv: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        unsafe { self.as_ref().dyn_pure_readv(bufv, offset).await }
    }

    async unsafe fn pure_writev(&self, bufv: IoVector<'_>, offset: u64) -> io::Result<()> {
        unsafe { self.as_ref().dyn_pure_writev(bufv, offset).await }
    }

    async unsafe fn pure_write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        unsafe { self.as_ref().dyn_pure_write_zeroes(offset, length).await }
    }

    async unsafe fn pure_discard(&self, offset: u64, length: u64) -> io::Result<()> {
        unsafe { self.as_ref().dyn_pure_discard(offset, length).await }
    }

    async fn flush(&self) -> io::Result<()> {
        self.as_ref().dyn_flush().await
    }

    async fn sync(&self) -> io::Result<()> {
        self.as_ref().dyn_sync().await
    }

    fn get_storage_helper(&self) -> &CommonStorageHelper {
        self.as_ref().dyn_get_storage_helper()
    }
}

impl Storage for Arc<dyn DynStorage> {
    async fn open(opts: StorageOpenOptions) -> io::Result<Self> {
        Box::<dyn DynStorage>::open(opts).await.map(Into::into)
    }

    fn mem_align(&self) -> usize {
        self.as_ref().dyn_mem_align()
    }

    fn req_align(&self) -> usize {
        self.as_ref().dyn_req_align()
    }

    fn zero_align(&self) -> usize {
        self.as_ref().dyn_zero_align()
    }

    fn discard_align(&self) -> usize {
        self.as_ref().dyn_discard_align()
    }

    fn size(&self) -> io::Result<u64> {
        self.as_ref().dyn_size()
    }

    fn resolve_relative_path<P: AsRef<Path>>(&self, relative: P) -> io::Result<PathBuf> {
        self.as_ref().dyn_resolve_relative_path(relative.as_ref())
    }

    async unsafe fn pure_readv(&self, bufv: IoVectorMut<'_>, offset: u64) -> io::Result<()> {
        unsafe { self.as_ref().dyn_pure_readv(bufv, offset) }.await
    }

    async unsafe fn pure_writev(&self, bufv: IoVector<'_>, offset: u64) -> io::Result<()> {
        unsafe { self.as_ref().dyn_pure_writev(bufv, offset) }.await
    }

    async unsafe fn pure_write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        unsafe { self.as_ref().dyn_pure_write_zeroes(offset, length) }.await
    }

    async unsafe fn pure_discard(&self, offset: u64, length: u64) -> io::Result<()> {
        unsafe { self.as_ref().dyn_pure_discard(offset, length) }.await
    }

    async fn flush(&self) -> io::Result<()> {
        self.as_ref().dyn_flush().await
    }

    async fn sync(&self) -> io::Result<()> {
        self.as_ref().dyn_sync().await
    }

    fn get_storage_helper(&self) -> &CommonStorageHelper {
        self.as_ref().dyn_get_storage_helper()
    }
}

impl StorageOpenOptions {
    /// Create default options.
    pub fn new() -> Self {
        StorageOpenOptions::default()
    }

    /// Set a filename to open.
    pub fn filename<P: AsRef<Path>>(mut self, filename: P) -> Self {
        self.filename = Some(filename.as_ref().to_owned());
        self
    }

    /// Whether the storage should be writable or not.
    pub fn write(mut self, write: bool) -> Self {
        self.writable = write;
        self
    }

    /// Whether to bypass the host page cache (if applicable).
    pub fn direct(mut self, direct: bool) -> Self {
        self.direct = direct;
        self
    }
}

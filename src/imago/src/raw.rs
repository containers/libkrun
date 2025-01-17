//! Access generic files as images.
//!
//! Allows accessing generic storage objects (`Storage`) as images (i.e. `FormatAccess`).

use crate::format::drivers::{FormatDriverInstance, Mapping};
use crate::{Storage, StorageOpenOptions};
use async_trait::async_trait;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::path::Path;

/// Wraps a storage object without any translation.
#[derive(Debug)]
pub struct Raw<S: Storage> {
    /// Wrapped storage object.
    inner: S,

    /// Whether this image may be modified.
    writable: bool,

    /// Disk size, which is the file size when this object was created.
    size: u64,
}

impl<S: Storage> Raw<S> {
    /// Wrap `inner`, allowing it to be used as a disk image in raw format.
    pub async fn open_image(inner: S, writable: bool) -> io::Result<Self> {
        let size = inner.size()?;
        Ok(Raw {
            inner,
            writable,
            size,
        })
    }

    /// Open the given path as a storage object, and wrap it in `Raw`.
    pub async fn open_path<P: AsRef<Path>>(path: P, writable: bool) -> io::Result<Self> {
        let storage_opts = StorageOpenOptions::new().write(writable).filename(path);
        let inner = S::open(storage_opts).await?;
        Self::open_image(inner, writable).await
    }

    /// Wrap `inner`, allowing it to be used as a disk image in raw format.
    #[cfg(feature = "sync-wrappers")]
    pub fn open_image_sync(inner: S, writable: bool) -> io::Result<Self> {
        let size = inner.size()?;
        Ok(Raw {
            inner,
            writable,
            size,
        })
    }

    /// Synchronous wrapper around [`Raw::open_path()`].
    pub fn open_path_sync<P: AsRef<Path>>(path: P, writable: bool) -> io::Result<Self> {
        tokio::runtime::Builder::new_current_thread()
            .build()?
            .block_on(Self::open_path(path, writable))
    }
}

#[async_trait(?Send)]
impl<S: Storage> FormatDriverInstance for Raw<S> {
    type Storage = S;

    fn size(&self) -> u64 {
        self.size
    }

    fn collect_storage_dependencies(&self) -> Vec<&S> {
        vec![&self.inner]
    }

    fn writable(&self) -> bool {
        self.writable
    }

    async fn get_mapping<'a>(
        &'a self,
        offset: u64,
        max_length: u64,
    ) -> io::Result<(Mapping<'a, S>, u64)> {
        let remaining = match self.size.checked_sub(offset) {
            None | Some(0) => return Ok((Mapping::Eof, 0)),
            Some(remaining) => remaining,
        };

        Ok((
            Mapping::Raw {
                storage: &self.inner,
                offset,
                writable: true,
            },
            std::cmp::min(max_length, remaining),
        ))
    }

    async fn ensure_data_mapping<'a>(
        &'a self,
        offset: u64,
        length: u64,
        _overwrite: bool,
    ) -> io::Result<(&'a S, u64, u64)> {
        let Some(remaining) = self.size.checked_sub(offset) else {
            return Err(io::Error::other("Cannot allocate past the end of file"));
        };
        if length > remaining {
            return Err(io::Error::other("Cannot allocate past the end of file"));
        }

        Ok((&self.inner, offset, length))
    }

    async fn flush(&self) -> io::Result<()> {
        // No internal buffers to flush
        self.inner.flush().await
    }

    async fn sync(&self) -> io::Result<()> {
        self.inner.sync().await
    }
}

impl<S: Storage> Display for Raw<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "raw[{}]", self.inner)
    }
}

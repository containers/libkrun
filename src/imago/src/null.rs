//! Null storage.
//!
//! Discard all written data, and return zeroes when read.

use crate::io_buffers::{IoVector, IoVectorMut};
use crate::storage::drivers::CommonStorageHelper;
use crate::Storage;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

/// Null storage object.
///
/// Reading from this will always return zeroes, writing to it does nothing (except to potentially
/// grow its virtual “file length”).
#[derive(Debug)]
pub struct Null {
    /// Virtual “file length”.
    size: AtomicU64,

    /// Storage helper.
    common_storage_helper: CommonStorageHelper,
}

impl Null {
    /// Create a new null storage object with the given initial virtual size.
    pub fn new(size: u64) -> Self {
        Null {
            size: size.into(),
            common_storage_helper: Default::default(),
        }
    }
}

impl Storage for Null {
    fn size(&self) -> io::Result<u64> {
        Ok(self.size.load(Ordering::Relaxed))
    }

    async unsafe fn pure_readv(&self, mut bufv: IoVectorMut<'_>, _offset: u64) -> io::Result<()> {
        bufv.fill(0);
        Ok(())
    }

    async unsafe fn pure_writev(&self, bufv: IoVector<'_>, offset: u64) -> io::Result<()> {
        let Some(end) = offset.checked_add(bufv.len()) else {
            return Err(io::Error::other("Write too long"));
        };

        self.size.fetch_max(end, Ordering::Relaxed);
        Ok(())
    }

    async unsafe fn pure_write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        let Some(end) = offset.checked_add(length) else {
            return Err(io::Error::other("Write too long"));
        };

        self.size.fetch_max(end, Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        // Nothing to do, there are no buffers
        Ok(())
    }

    async fn sync(&self) -> io::Result<()> {
        // Nothing to do, there is no hardware
        Ok(())
    }

    fn get_storage_helper(&self) -> &CommonStorageHelper {
        &self.common_storage_helper
    }
}

impl Display for Null {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "null:[{}B]", self.size.load(Ordering::Relaxed))
    }
}

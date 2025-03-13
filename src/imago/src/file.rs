//! Use a plain as storage.

use crate::io_buffers::{IoVector, IoVectorMut};
use crate::storage::drivers::CommonStorageHelper;
use crate::{Storage, StorageOpenOptions};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Write};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(all(unix, not(target_os = "macos")))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::{FileExt, OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
#[cfg(windows)]
use windows_sys::Win32::System::Ioctl::{FILE_ZERO_DATA_INFORMATION, FSCTL_SET_ZERO_DATA};
#[cfg(windows)]
use windows_sys::Win32::System::IO::DeviceIoControl;

/// Use a plain file as storage objects.
#[derive(Debug)]
pub struct File {
    /// The file.
    file: RwLock<fs::File>,

    /// Whether we are using direct I/O.
    direct_io: bool,

    /// For debug purposes, and to resolve relative filenames.
    filename: Option<PathBuf>,

    /// Cached file length.
    ///
    /// Third parties changing the length concurrently is pretty certain to break things anyway.
    size: AtomicU64,

    /// Storage helper.
    common_storage_helper: CommonStorageHelper,
}

impl TryFrom<fs::File> for File {
    type Error = io::Error;

    /// Use the given existing `std::fs::File`.
    ///
    /// Convert the given existing `std::fs::File` object into an imago storage object.
    ///
    /// When using this, the resulting object will not know its own filename.  That makes it
    /// impossible to auto-resolve relative paths to it, e.g. qcow2 backing file names.
    fn try_from(file: fs::File) -> io::Result<Self> {
        let size = get_file_size(&file)?;

        Ok(File {
            file: RwLock::new(file),
            // TODO: Find out, or better yet, drop `direct_io` and just probe the alignment.
            direct_io: false,
            filename: None,
            size: AtomicU64::new(size),
            common_storage_helper: Default::default(),
        })
    }
}

impl Storage for File {
    async fn open(opts: StorageOpenOptions) -> io::Result<Self> {
        Self::do_open_sync(opts)
    }

    #[cfg(feature = "sync-wrappers")]
    fn open_sync(opts: StorageOpenOptions) -> io::Result<Self> {
        Self::do_open_sync(opts)
    }

    fn mem_align(&self) -> usize {
        // TODO: Probe
        if self.direct_io {
            4096
        } else {
            1
        }
    }

    fn req_align(&self) -> usize {
        // TODO: Probe
        if self.direct_io {
            4096
        } else {
            1
        }
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.size.load(Ordering::Relaxed))
    }

    fn resolve_relative_path<P: AsRef<Path>>(&self, relative: P) -> io::Result<PathBuf> {
        let relative = relative.as_ref();

        if relative.is_absolute() {
            return Ok(relative.to_path_buf());
        }

        let filename = self
            .filename
            .as_ref()
            .ok_or_else(|| io::Error::other("No filename set for base image"))?;

        let dirname = filename
            .parent()
            .ok_or_else(|| io::Error::other("Invalid base image filename set"))?;

        Ok(dirname.join(relative))
    }

    #[cfg(unix)]
    async unsafe fn pure_readv(
        &self,
        mut bufv: IoVectorMut<'_>,
        mut offset: u64,
    ) -> io::Result<()> {
        while !bufv.is_empty() {
            let iovec = unsafe { bufv.as_iovec() };
            let result = unsafe {
                libc::preadv(
                    self.file.read().unwrap().as_raw_fd(),
                    iovec.as_ptr(),
                    iovec.len() as libc::c_int,
                    offset
                        .try_into()
                        .map_err(|_| io::Error::other("Read offset overflow"))?,
                )
            };

            let len = if result < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            } else {
                result as u64
            };

            if len == 0 {
                // End of file
                bufv.fill(0);
                break;
            }

            bufv = bufv.split_tail_at(len);
            offset = offset
                .checked_add(len)
                .ok_or_else(|| io::Error::other("Read offset overflow"))?;
        }

        Ok(())
    }

    #[cfg(windows)]
    async unsafe fn pure_readv(&self, bufv: IoVectorMut<'_>, mut offset: u64) -> io::Result<()> {
        for mut buffer in bufv.into_inner() {
            let mut buffer: &mut [u8] = &mut buffer;
            while !buffer.is_empty() {
                let len = if offset >= self.size.load(Ordering::Relaxed) {
                    buffer.fill(0);
                    buffer.len()
                } else {
                    self.file.write().unwrap().seek_read(buffer, offset)?
                };
                offset = offset
                    .checked_add(len as u64)
                    .ok_or_else(|| io::Error::other("Read offset overflow"))?;
                buffer = buffer.split_at_mut(len).1;
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    async unsafe fn pure_writev(&self, mut bufv: IoVector<'_>, mut offset: u64) -> io::Result<()> {
        while !bufv.is_empty() {
            let iovec = unsafe { bufv.as_iovec() };
            let result = unsafe {
                libc::pwritev(
                    self.file.read().unwrap().as_raw_fd(),
                    iovec.as_ptr(),
                    iovec.len() as libc::c_int,
                    offset
                        .try_into()
                        .map_err(|_| io::Error::other("Write offset overflow"))?,
                )
            };

            let len = if result < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            } else {
                result as u64
            };

            if result == 0 {
                // Should not happen, i.e. is an error
                return Err(io::ErrorKind::WriteZero.into());
            }

            bufv = bufv.split_tail_at(len);
            offset = offset
                .checked_add(len)
                .ok_or_else(|| io::Error::other("Write offset overflow"))?;
            self.size.fetch_max(offset, Ordering::Relaxed);
        }

        Ok(())
    }

    #[cfg(windows)]
    async unsafe fn pure_writev(&self, bufv: IoVector<'_>, mut offset: u64) -> io::Result<()> {
        for buffer in bufv.into_inner() {
            let mut buffer: &[u8] = &buffer;
            while !buffer.is_empty() {
                let len = self.file.write().unwrap().seek_write(buffer, offset)?;
                offset = offset
                    .checked_add(len as u64)
                    .ok_or_else(|| io::Error::other("Write offset overflow"))?;
                self.size.fetch_max(offset, Ordering::Relaxed);
                buffer = buffer.split_at(len).1;
            }
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
    async unsafe fn pure_write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        // All of our discard methods also ensure the range reads back as zeroes
        unsafe { self.pure_discard(offset, length) }.await
    }

    // Beware when adding new discard methods: This is called by `pure_write_zeroes()`, so the
    // current expectation is that discarded ranges will read back as zeroes.  If the new method
    // does not guarantee that, you will need to modify `pure_write_zeroes()`.
    #[cfg(target_os = "linux")]
    async unsafe fn pure_discard(&self, offset: u64, length: u64) -> io::Result<()> {
        if self.try_discard_by_truncate(offset, length)? {
            return Ok(());
        }

        // If offset or length are too big, just skip discarding.
        let Ok(offset) = libc::off_t::try_from(offset) else {
            return Ok(());
        };
        let Ok(length) = libc::off_t::try_from(length) else {
            return Ok(());
        };

        let file = self.file.read().unwrap();
        // Safe: File descriptor is valid, and the rest are simple integer parameters.
        let ret = unsafe {
            libc::fallocate(
                file.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                offset,
                length,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    // Beware when adding new discard methods: This is called by `pure_write_zeroes()`, so the
    // current expectation is that discarded ranges will read back as zeroes.  If the new method
    // does not guarantee that, you will need to modify `pure_write_zeroes()`.
    #[cfg(windows)]
    async unsafe fn pure_discard(&self, offset: u64, length: u64) -> io::Result<()> {
        if self.try_discard_by_truncate(offset, length)? {
            return Ok(());
        }

        // If offset or length are too big, just skip discarding.
        let Ok(offset) = i64::try_from(offset) else {
            return Ok(());
        };
        let Ok(length) = i64::try_from(length) else {
            return Ok(());
        };

        let end = offset.saturating_add(length).saturating_add(1);
        let params = FILE_ZERO_DATA_INFORMATION {
            FileOffset: offset,
            BeyondFinalZero: end,
        };
        let mut _returned = 0;
        let file = self.file.read().unwrap();
        // Safe: File handle is valid, mandatory pointers (input, returned length) are passed and
        // valid, the parameter type matches the call, and the input size matches the object
        // passed.
        let ret = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_ZERO_DATA,
                (&params as *const FILE_ZERO_DATA_INFORMATION).cast::<std::ffi::c_void>(),
                size_of_val(&params) as u32,
                std::ptr::null_mut(),
                0,
                &mut _returned,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    // Beware when adding new discard methods: This is called by `pure_write_zeroes()`, so the
    // current expectation is that discarded ranges will read back as zeroes.  If the new method
    // does not guarantee that, you will need to modify `pure_write_zeroes()`.
    #[cfg(target_os = "macos")]
    async unsafe fn pure_discard(&self, offset: u64, length: u64) -> io::Result<()> {
        if self.try_discard_by_truncate(offset, length)? {
            return Ok(());
        }

        // If offset or length are too big, just skip discarding.
        let Ok(offset) = libc::off_t::try_from(offset) else {
            return Ok(());
        };
        let Ok(length) = libc::off_t::try_from(length) else {
            return Ok(());
        };

        let params = libc::fpunchhole_t {
            fp_flags: 0,
            reserved: 0,
            fp_offset: offset,
            fp_length: length,
        };
        let file = self.file.read().unwrap();
        // Safe: FD is valid, passed pointer is valid and its type matches the call.
        let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &params) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        self.file.write().unwrap().flush()
    }

    async fn sync(&self) -> io::Result<()> {
        self.file.write().unwrap().sync_all()
    }

    fn get_storage_helper(&self) -> &CommonStorageHelper {
        &self.common_storage_helper
    }
}

impl File {
    /// Implementation for [`File::open()`] and [`File::open_sync()`].
    fn do_open_sync(opts: StorageOpenOptions) -> io::Result<Self> {
        let Some(filename) = opts.filename else {
            return Err(io::Error::other("Filename required"));
        };

        let mut file_opts = fs::OpenOptions::new();
        file_opts.read(true).write(opts.writable);
        #[cfg(not(target_os = "macos"))]
        if opts.direct {
            file_opts.custom_flags(
                #[cfg(unix)]
                libc::O_DIRECT,
                #[cfg(windows)]
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_NO_BUFFERING,
            );
        }

        let filename_owned = filename.to_owned();
        let file = file_opts.open(filename)?;

        let size = get_file_size(&file)?;

        #[cfg(target_os = "macos")]
        if opts.direct {
            // Safe: We check the return value.
            let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                return Err(io::Error::new(
                    err.kind(),
                    format!("Failed to disable host cache: {err}"),
                ));
            }
        }

        Ok(File {
            file: RwLock::new(file),
            direct_io: opts.direct,
            filename: Some(filename_owned),
            size: AtomicU64::new(size),
            common_storage_helper: Default::default(),
        })
    }

    /// Attempt to discard range by truncating the file.
    ///
    /// If the given range is at the end of the file, discard it by simply truncating the file.
    /// Return `true` on success.
    ///
    /// If the range is not at the end of the file, i.e. another method of discarding is needed,
    /// return `false`.
    fn try_discard_by_truncate(&self, offset: u64, length: u64) -> io::Result<bool> {
        // Prevent modifications to the file length
        #[allow(clippy::readonly_write_lock)]
        let file = self.file.write().unwrap();

        let size = self.size.load(Ordering::Relaxed);
        if offset >= size {
            // Nothing to do
            return Ok(true);
        }

        // If `offset + length` overflows, we can just assume it ends at `size`.  (Anything past
        // `size is irrelevant anyway.)
        let end = offset.checked_add(length).unwrap_or(size);
        if end < size {
            return Ok(false);
        }

        file.set_len(offset)?;
        Ok(true)
    }
}

impl Display for File {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(filename) = self.filename.as_ref() {
            write!(f, "file:{filename:?}")
        } else {
            write!(f, "file:<unknown path>")
        }
    }
}

fn get_file_size(file: &fs::File) -> io::Result<u64> {
    file.metadata().and_then(|m| {
        #[cfg(windows)]
        let is_block_device = false;
        #[cfg(unix)]
        let is_block_device = m.file_type().is_block_device();

        if is_block_device {
            get_block_device_size(file)
        } else {
            Ok(m.len())
        }
    })
}

#[cfg(windows)]
fn get_block_device_size(file: &fs::File) -> io::Result<u64> {
    unreachable!("never called on Windows")
}

#[cfg(target_os = "linux")]
fn get_block_device_size(file: &fs::File) -> io::Result<u64> {
    let mut size: u64 = 0;
    unsafe { ioctl::blkgetsize64(file.as_raw_fd(), &mut size) }?;
    Ok(size)
}

#[cfg(target_os = "macos")]
fn get_block_device_size(file: &fs::File) -> io::Result<u64> {
    let mut block_size: u32 = 0;
    unsafe { ioctl::dkiocgetblocksize(file.as_raw_fd(), &mut block_size) }?;
    let mut block_count: u64 = 0;
    unsafe { ioctl::dkiocgetblockcount(file.as_raw_fd(), &mut block_count) }?;
    Ok(u64::from(block_size) * block_count)
}

#[allow(missing_docs)]
mod ioctl {
    #[cfg(unix)]
    use nix::ioctl_read;

    // https://github.com/torvalds/linux/blob/master/include/uapi/linux/fs.h#L200

    #[cfg(target_os = "linux")]
    ioctl_read!(blkgetsize64, 0x12, 114, u64);

    // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/disk.h#L198-L199

    #[cfg(target_os = "macos")]
    ioctl_read!(dkiocgetblocksize, b'd', 24, u32);

    #[cfg(target_os = "macos")]
    ioctl_read!(dkiocgetblockcount, b'd', 25, u64);
}

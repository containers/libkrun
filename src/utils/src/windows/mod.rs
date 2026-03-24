use windows_sys::Win32::Foundation::HANDLE;

pub(crate) mod bindings;
pub mod epoll;
pub mod eventfd;

/// Cross-platform alias used by the rest of the codebase.  On Windows this
/// is just [`HANDLE`] — the two names are interchangeable.
pub type RawFd = HANDLE;

/// Windows equivalent of [`std::os::unix::io::AsRawFd`].
pub trait AsRawFd {
    fn as_raw_fd(&self) -> RawFd;
}

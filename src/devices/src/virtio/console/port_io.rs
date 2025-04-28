use std::fs::File;
use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
use log::Level;
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags};
use nix::unistd::dup;
use utils::eventfd::EventFd;
use utils::eventfd::EFD_NONBLOCK;
use vm_memory::bitmap::Bitmap;
use vm_memory::{VolatileMemoryError, VolatileSlice, WriteVolatile};

pub trait PortInput {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_readable(&self, stopfd: Option<&EventFd>);
}

pub trait PortOutput {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_writable(&self);
}

pub fn stdin() -> Result<Box<dyn PortInput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(STDIN_FILENO)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortInputFd(fd)))
}

pub fn stdout() -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(STDOUT_FILENO)
}

pub fn stderr() -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(STDERR_FILENO)
}

pub fn input_empty() -> Result<Box<dyn PortInput + Send>, nix::Error> {
    Ok(Box::new(PortInputEmpty {}))
}

pub fn output_file(file: File) -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(file.as_raw_fd())
}

pub fn output_to_raw_fd_dup(fd: RawFd) -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(fd)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortOutputFd(fd)))
}

pub fn output_to_log_as_err() -> Box<dyn PortOutput + Send> {
    Box::new(PortOutputLog::new())
}

struct PortInputFd(OwnedFd);

impl AsRawFd for PortInputFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl PortInput for PortInputFd {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> io::Result<usize> {
        // This source code is copied from vm-memory, except it fixes an issue, where
        // the original code would does not handle handle EWOULDBLOCK

        let fd = self.as_raw_fd();
        let guard = buf.ptr_guard_mut();

        let dst = guard.as_ptr().cast::<libc::c_void>();

        // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `dst` is
        // valid for writes of length `buf.len() by the invariants upheld by the constructor
        // of `VolatileSlice`.
        let bytes_read = unsafe { libc::read(fd, dst, buf.len()) };

        if bytes_read < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::WouldBlock {
                // We don't know if a partial read might have happened, so mark everything as dirty
                buf.bitmap().mark_dirty(0, buf.len());
            }

            Err(err)
        } else {
            let bytes_read = bytes_read.try_into().unwrap();
            buf.bitmap().mark_dirty(0, bytes_read);
            Ok(bytes_read)
        }
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let mut poll_fds = Vec::new();
        poll_fds.push(PollFd::new(self.as_raw_fd(), PollFlags::POLLIN));
        if let Some(stopfd) = stopfd {
            poll_fds.push(PollFd::new(stopfd.as_raw_fd(), PollFlags::POLLIN));
        }
        poll(&mut poll_fds, -1).expect("Failed to poll");
    }
}

struct PortOutputFd(OwnedFd);

impl AsRawFd for PortOutputFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl PortOutput for PortOutputFd {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        self.0.write_volatile(buf).map_err(|e| match e {
            VolatileMemoryError::IOError(e) => e,
            e => {
                log::error!("Unsuported error from write_volatile: {e:?}");
                io::Error::other(e)
            }
        })
    }

    fn wait_until_writable(&self) {
        let mut poll_fds = [PollFd::new(self.as_raw_fd(), PollFlags::POLLOUT)];
        poll(&mut poll_fds, -1).expect("Failed to poll");
    }
}

fn dup_raw_fd_into_owned(raw_fd: RawFd) -> Result<OwnedFd, nix::Error> {
    let fd = dup(raw_fd)?;
    // SAFETY: the fd is valid because dup succeeded
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn make_non_blocking(as_rw_fd: &impl AsRawFd) -> Result<(), nix::Error> {
    let fd = as_rw_fd.as_raw_fd();
    unsafe {
        let flags = fcntl(fd, F_GETFL, 0);
        if flags < 0 {
            return Err(Errno::last());
        }

        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(Errno::last());
        }
    }
    Ok(())
}

// Utility to relay log from the VM (the kernel boot log and messages from init)
// to the rust log
#[derive(Default)]
pub struct PortOutputLog {
    buf: Vec<u8>,
}

impl PortOutputLog {
    const FORCE_FLUSH_TRESHOLD: usize = 512;
    const LOG_TARGET: &'static str = "init_or_kernel";

    fn new() -> Self {
        Self::default()
    }

    fn force_flush(&mut self) {
        log::log!(target: PortOutputLog::LOG_TARGET, Level::Error, "[missing newline]{}", String::from_utf8_lossy(&self.buf));
        self.buf.clear();
    }
}

impl PortOutput for PortOutputLog {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        self.buf.write_volatile(buf).map_err(io::Error::other)?;

        let mut start = 0;
        for (i, ch) in self.buf.iter().cloned().enumerate() {
            if ch == b'\n' {
                log::log!(target: PortOutputLog::LOG_TARGET, Level::Error, "{}", String::from_utf8_lossy(&self.buf[start..i]));
                start = i + 1;
            }
        }
        self.buf.drain(0..start);
        // Make sure to not grow the internal buffer forever!
        if self.buf.len() > PortOutputLog::FORCE_FLUSH_TRESHOLD {
            self.force_flush()
        }
        Ok(buf.len())
    }

    fn wait_until_writable(&self) {}
}

pub struct PortInputSigInt {
    sigint_evt: EventFd,
}

impl PortInputSigInt {
    pub fn new() -> Self {
        PortInputSigInt {
            sigint_evt: EventFd::new(EFD_NONBLOCK)
                .expect("Failed to create EventFd for SIGINT signaling"),
        }
    }

    pub fn sigint_evt(&self) -> &EventFd {
        &self.sigint_evt
    }
}

impl Default for PortInputSigInt {
    fn default() -> Self {
        Self::new()
    }
}

impl PortInput for PortInputSigInt {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error> {
        self.sigint_evt.read()?;
        log::trace!("SIGINT received");
        buf.copy_from(&[3u8]); //ASCII 'ETX' -> generates SIGINIT in a terminal
        Ok(1)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let mut poll_fds = Vec::with_capacity(2);
        poll_fds.push(PollFd::new(self.sigint_evt.as_raw_fd(), PollFlags::POLLIN));
        if let Some(stopfd) = stopfd {
            poll_fds.push(PollFd::new(stopfd.as_raw_fd(), PollFlags::POLLIN));
        }

        poll(&mut poll_fds, -1).expect("Failed to poll");
    }
}

pub struct PortInputEmpty {}

impl PortInputEmpty {
    pub fn new() -> Self {
        PortInputEmpty {}
    }
}

impl Default for PortInputEmpty {
    fn default() -> Self {
        Self::new()
    }
}

impl PortInput for PortInputEmpty {
    fn read_volatile(&mut self, _buf: &mut VolatileSlice) -> Result<usize, io::Error> {
        Ok(0)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        if let Some(stopfd) = stopfd {
            let mut poll_fds = [PollFd::new(stopfd.as_raw_fd(), PollFlags::POLLIN)];
            poll(&mut poll_fds, -1).expect("Failed to poll");
        } else {
            std::thread::sleep(std::time::Duration::MAX);
        }
    }
}

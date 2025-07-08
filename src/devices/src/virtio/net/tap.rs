use libc::{
    c_char, c_int, ifreq, IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, O_RDWR, TUN_F_CSUM, TUN_F_TSO4,
    TUN_F_TSO6,
};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::unistd::{read, write};
use nix::{ioctl_write_int, ioctl_write_ptr};
use std::os::fd::{AsRawFd, RawFd};
use std::{io, mem, ptr};

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};

ioctl_write_ptr!(tunsetiff, b'T', 202, c_int);
ioctl_write_int!(tunsetoffload, b'T', 208);
ioctl_write_ptr!(tunsetvnethdrsz, b'T', 216, c_int);

pub struct Tap {
    fd: RawFd,
}

impl Tap {
    /// Create an endpoint using the file descriptor of a tap device
    pub fn new(tap_name: String) -> Result<Self, ConnectError> {
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr() as *const _, O_RDWR) };

        if fd < 0 {
            return Err(ConnectError::OpenNetTun(io::Error::from_raw_os_error(fd)));
        }

        let mut req: ifreq = unsafe { mem::zeroed() };

        unsafe {
            ptr::copy_nonoverlapping(
                tap_name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                tap_name.len(),
            );
        }

        req.ifr_ifru.ifru_flags = IFF_TAP as i16 | IFF_NO_PI as i16 | IFF_VNET_HDR as i16;

        unsafe {
            if let Err(err) = tunsetiff(fd, &mut req as *mut _ as *mut _) {
                return Err(ConnectError::TunSetIff(io::Error::from(err)));
            }

            // TODO(slp): replace hardcoded vnet size with cons
            if let Err(err) = tunsetvnethdrsz(fd, &12) {
                return Err(ConnectError::TunSetVnetHdrSz(io::Error::from(err)));
            }

            if let Err(err) = tunsetoffload(fd, (TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6) as u64) {
                return Err(ConnectError::TunSetOffload(io::Error::from(err)));
            }
        }

        match fcntl(fd, FcntlArg::F_GETFL) {
            Ok(flags) => {
                if let Err(e) = fcntl(
                    fd,
                    FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
                ) {
                    warn!("error switching to non-blocking: id={fd}, err={e}");
                }
            }
            Err(e) => error!("couldn't obtain fd flags id={fd}, err={e}"),
        };

        Ok(Self { fd })
    }
}

impl NetBackend for Tap {
    /// Try to read a frame from the tap devie. If no bytes are available reports
    /// ReadError::NothingRead.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let frame_length = match read(self.fd, buf) {
            Ok(f) => f,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                return Err(ReadError::NothingRead)
            }
            Err(e) => {
                return Err(ReadError::Internal(e));
            }
        };
        debug!("Read eth frame from tap: {frame_length} bytes");
        Ok(frame_length)
    }

    /// Try to write a frame to the tap device.
    fn write_frame(&mut self, _hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        let ret = write(self.fd, buf).map_err(WriteError::Internal)?;
        debug!("Written frame size={}, written={}", buf.len(), ret);
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        false
    }

    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        // The tap backend doesn't do partial writes.
        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

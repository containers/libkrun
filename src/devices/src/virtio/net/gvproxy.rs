use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{
    bind, getsockopt, recv, sendto, setsockopt, socket, sockopt, AddressFamily, MsgFlags, SockFlag,
    SockType, UnixAddr,
};
use nix::unistd::unlink;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};

const VFKIT_MAGIC: [u8; 4] = *b"VFKT";

pub struct Gvproxy {
    fd: RawFd,
    peer_addr: UnixAddr,
}

impl Gvproxy {
    /// Connect to a running gvproxy instance, given a socket file descriptor
    pub fn new(path: PathBuf) -> Result<Self, ConnectError> {
        let fd = socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(ConnectError::CreateSocket)?;
        let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
        let local_addr = UnixAddr::new(&PathBuf::from(format!("{}-krun.sock", path.display())))
            .map_err(ConnectError::InvalidAddress)?;
        if let Some(path) = local_addr.path() {
            _ = unlink(path);
        }
        bind(fd, &local_addr).map_err(ConnectError::Binding)?;

        sendto(fd, &VFKIT_MAGIC, &peer_addr, MsgFlags::empty())
            .map_err(ConnectError::SendingMagic)?;

        // macOS forces us to do this here instead of just using SockFlag::SOCK_NONBLOCK above.
        match fcntl(fd, FcntlArg::F_GETFL) {
            Ok(flags) => match OFlag::from_bits(flags) {
                Some(flags) => {
                    if let Err(e) = fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                        warn!("error switching to non-blocking: id={}, err={}", fd, e);
                    }
                }
                None => error!("invalid fd flags id={}", fd),
            },
            Err(e) => error!("couldn't obtain fd flags id={}, err={}", fd, e),
        };

        setsockopt(fd, sockopt::ReusePort, &true).unwrap();
        #[cfg(target_os = "macos")]
        {
            // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
            let option_value: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &option_value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&option_value) as libc::socklen_t,
                )
            };
        }

        if let Err(e) = setsockopt(fd, sockopt::SndBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }
        if let Err(e) = setsockopt(fd, sockopt::RcvBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "passt socket (fd {fd}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(fd, sockopt::SndBuf),
            getsockopt(fd, sockopt::RcvBuf)
        );

        Ok(Self { fd, peer_addr })
    }
}

impl NetBackend for Gvproxy {
    /// Try to read a frame from passt. If no bytes are available reports ReadError::NothingRead
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let frame_length = match recv(self.fd, buf, MsgFlags::empty()) {
            Ok(f) => f,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                return Err(ReadError::NothingRead)
            }
            Err(e) => {
                return Err(ReadError::Internal(e));
            }
        };
        debug!("Read eth frame from passt: {} bytes", frame_length);
        Ok(frame_length)
    }

    /// Try to write a frame to passt.
    /// (Will mutate and override parts of buf, with a passt header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet frame,
    ///               (such as vnet header), that can be overwritten.
    ///               must be >= PASST_HEADER_LEN
    /// * `buf` - the buffer to write to passt, `buf[..hdr_len]` may be overwritten
    ///
    /// If this function returns WriteError::PartialWrite, you have to finish the write using
    /// try_finish_write.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        let ret = sendto(self.fd, &buf[hdr_len..], &self.peer_addr, MsgFlags::empty())
            .map_err(WriteError::Internal)?;
        debug!(
            "Written frame size={}, written={}",
            buf.len() - hdr_len,
            ret
        );
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        false
    }

    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        // The gvproxy backend doesn't do partial writes.
        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

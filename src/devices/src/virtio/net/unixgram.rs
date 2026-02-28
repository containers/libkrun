#[cfg(target_os = "macos")]
use libc::c_int;
use libc::iovec;
#[cfg(target_os = "linux")]
use libc::mmsghdr;
use nix::sys::socket::{
    bind, connect, getsockopt, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
use std::fs::remove_file;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use utils::fd::SetNonblockingExt;
use vm_memory::GuestMemoryMmap;

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use crate::virtio::batch_queue::iovec_utils::{advance_tx_iovecs_vec, write_to_iovecs};
use crate::virtio::batch_queue::{ChainsMemoryRepr, ReceivedLen, RxQueueProducer, TxQueueConsumer};
use crate::virtio::queue::Queue;
use crate::virtio::InterruptTransport;

#[cfg(target_os = "macos")]
use super::socket_x::msghdr_x;

const VFKIT_MAGIC: [u8; 4] = *b"VFKT";

// ============================================================================
// MsgHdr - Chain representation that IS an mmsghdr/msghdr_x
// ============================================================================

#[cfg(target_os = "linux")]
type RawMsgHdr = mmsghdr;

#[cfg(target_os = "macos")]
type RawMsgHdr = msghdr_x;

/// Chain representation that wraps mmsghdr/msghdr_x.
///
/// The iovec pointer is stored directly in the header, avoiding allocation
/// of a separate mmsghdr array for sendmmsg/sendmsg_x/recvmmsg/recvmsg_x.
///
/// For RX, use `received_len()` to get the kernel-filled byte count.
///
/// # Safety
/// Uses `mem::forget` to transfer iovec Vec ownership into the header.
/// The capacity is stored in `Meta` for proper cleanup via `Vec::from_raw_parts()`.
#[repr(transparent)]
pub struct MsgHdr(RawMsgHdr);

// Safety: The raw pointer inside points to heap memory that we have exclusive ownership of.
// Transferring to another thread is safe because we transfer ownership of the entire struct.
unsafe impl Send for MsgHdr {}

unsafe impl ChainsMemoryRepr for MsgHdr {
    /// Stores the Vec capacity for cleanup
    type Meta = usize;

    fn len(&self) -> usize {
        #[cfg(target_os = "linux")]
        {
            self.0.msg_hdr.msg_iovlen
        }
        #[cfg(target_os = "macos")]
        {
            self.0.msg_iovlen as usize
        }
    }

    fn total_bytes(&self) -> usize {
        let (ptr, len) = self.iov_ptr_len();
        if ptr.is_null() {
            0
        } else {
            let slices = unsafe { std::slice::from_raw_parts(ptr as *const iovec, len) };
            slices.iter().map(|s| s.iov_len).sum()
        }
    }

    fn clear(&mut self, capacity: &mut Self::Meta) {
        let (ptr, len) = self.iov_ptr_len();
        if !ptr.is_null() {
            // Reconstruct Vec to drop it properly
            unsafe {
                let _: Vec<iovec> = Vec::from_raw_parts(ptr, len, *capacity);
            }
            self.set_iov_null();
            *capacity = 0;
        }
    }
}

impl MsgHdr {
    /// Create MsgHdr from raw iovec pointer and length.
    #[inline]
    fn from_raw(iov_ptr: *mut iovec, len: usize) -> Self {
        #[cfg(target_os = "linux")]
        {
            let mut hdr: mmsghdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_iov = iov_ptr;
            hdr.msg_hdr.msg_iovlen = len;
            Self(hdr)
        }

        #[cfg(target_os = "macos")]
        {
            Self(msghdr_x {
                msg_iov: iov_ptr,
                msg_iovlen: len as c_int,
                ..Default::default()
            })
        }
    }

    #[inline]
    fn iov_ptr_len(&self) -> (*mut iovec, usize) {
        #[cfg(target_os = "linux")]
        {
            (self.0.msg_hdr.msg_iov, self.0.msg_hdr.msg_iovlen)
        }
        #[cfg(target_os = "macos")]
        {
            (self.0.msg_iov, self.0.msg_iovlen as usize)
        }
    }

    #[inline]
    fn set_iov_null(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.0.msg_hdr.msg_iov = std::ptr::null_mut();
            self.0.msg_hdr.msg_iovlen = 0;
        }
        #[cfg(target_os = "macos")]
        {
            self.0.msg_iov = std::ptr::null_mut();
            self.0.msg_iovlen = 0;
        }
    }
}

impl ReceivedLen for MsgHdr {
    #[cfg(target_os = "linux")]
    #[inline]
    fn received_len(&self) -> usize {
        self.0.msg_len as usize
    }

    #[cfg(target_os = "macos")]
    #[inline]
    fn received_len(&self) -> usize {
        self.0.msg_datalen
    }
}

pub struct Unixgram {
    fd: OwnedFd,
    include_vnet_header: bool,
    tx_consumer: TxQueueConsumer<MsgHdr>,
    rx_producer: RxQueueProducer<MsgHdr>,
}

impl Unixgram {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(
        fd: OwnedFd,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Self {
        // Ensure the socket is in non-blocking mode.
        if let Err(e) = fd.set_nonblocking(true) {
            log::error!("Failed to set O_NONBLOCK on unixgram socket: {e}");
        }

        #[cfg(target_os = "macos")]
        {
            // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
            let option_value: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &option_value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&option_value) as libc::socklen_t,
                )
            };
        }

        let tx_consumer = TxQueueConsumer::new(tx_queue, mem.clone(), interrupt.clone());
        let rx_producer = RxQueueProducer::new(rx_queue, mem, interrupt);

        Self {
            fd,
            include_vnet_header,
            tx_consumer,
            rx_producer,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(
        path: PathBuf,
        send_vfkit_magic: bool,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Result<Self, ConnectError> {
        // We cannot create a non-blocking socket on macOS here. This is done later in new().
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
            _ = remove_file(path);
        }
        bind(fd.as_raw_fd(), &local_addr).map_err(ConnectError::Binding)?;

        // Connect so we don't need to use the peer address again. This also
        // allows the server to remove the socket after the connection.
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

        if send_vfkit_magic {
            send(fd.as_raw_fd(), &VFKIT_MAGIC, MsgFlags::empty())
                .map_err(ConnectError::SendingMagic)?;
        }

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }
        if let Err(e) = setsockopt(&fd, sockopt::RcvBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_RCVBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Ok(Self::new(
            fd,
            include_vnet_header,
            tx_queue,
            rx_queue,
            mem,
            interrupt,
        ))
    }
}

impl NetBackend for Unixgram {
    fn send(&mut self) -> Result<(), WriteError> {
        let skip = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };

        // Feed frames from queue, skipping vnet header
        let fed = self.tx_consumer.feed_with_transform(|mut iovecs| {
            let orig_len = iovecs.len();
            let orig_bytes: usize = iovecs.iter().map(|s| s.len()).sum();
            if skip > 0 {
                advance_tx_iovecs_vec(&mut iovecs, skip);
            }
            let ptr = iovecs.as_mut_ptr() as *mut iovec;
            let len = iovecs.len();
            let cap = iovecs.capacity();
            let total_bytes: usize = unsafe {
                std::slice::from_raw_parts(ptr as *const iovec, len)
                    .iter()
                    .map(|iov| iov.iov_len)
                    .sum()
            };
            log::info!(
                "TX feed: orig_iovecs={} orig_bytes={} after_skip: iovecs={} bytes={} cap={}",
                orig_len,
                orig_bytes,
                len,
                total_bytes,
                cap
            );
            std::mem::forget(iovecs);
            (MsgHdr::from_raw(ptr, len), cap)
        });
        if fed > 0 {
            log::info!(
                "TX: fed {} chains, pending={}",
                fed,
                self.tx_consumer.pending_count()
            );
        }

        if !self.tx_consumer.has_pending() {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        self.send_linux()?;

        #[cfg(target_os = "macos")]
        self.send_macos()?;

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        let vnet_offset = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };
        log::info!(
            "recv: include_vnet_header={} vnet_offset={}",
            self.include_vnet_header,
            vnet_offset
        );

        // Feed chains from queue, writing vnet header and advancing iovecs during feed
        let rx_fed = self.rx_producer.feed_with_transform(|mut iovecs| {
            let orig_len = iovecs.len();
            let orig_bytes: usize = iovecs.iter().map(|s| s.len()).sum();
            if vnet_offset > 0 {
                // Write default vnet header to beginning of buffer
                write_to_iovecs(&mut iovecs, &super::DEFAULT_VNET_HDR);
                // Advance iovecs past vnet header so receive goes after it
                crate::virtio::batch_queue::iovec_utils::advance_iovecs_vec(
                    &mut iovecs,
                    vnet_offset,
                );
            }
            let ptr = iovecs.as_mut_ptr() as *mut iovec;
            let len = iovecs.len();
            let cap = iovecs.capacity();
            log::info!(
                "RX feed: orig_iovecs={} orig_bytes={} after_vnet: iovecs={} cap={}",
                orig_len,
                orig_bytes,
                len,
                cap
            );
            std::mem::forget(iovecs);
            (MsgHdr::from_raw(ptr, len), cap)
        });
        if rx_fed > 0 {
            log::info!(
                "RX: fed {} chains, pending={}",
                rx_fed,
                self.rx_producer.pending_count()
            );
        }

        #[cfg(target_os = "linux")]
        self.recv_linux();

        #[cfg(target_os = "macos")]
        self.recv_macos();

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
impl Unixgram {
    fn send_linux(&mut self) -> Result<(), WriteError> {
        let fd = self.fd.as_raw_fd();

        self.tx_consumer.consume(|batch| {
            let len = batch.len();
            let chains = batch.chains(0..len);
            let ptr = chains.as_ptr() as *mut mmsghdr;

            let ret = unsafe { libc::sendmmsg(fd, ptr, len as libc::c_uint, libc::MSG_DONTWAIT) };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                match err.kind() {
                    std::io::ErrorKind::WouldBlock => {}
                    _ => {
                        log::error!("sendmmsg failed: {err}");
                    }
                }
                return;
            }

            batch.finish_many(0..ret as usize);
        });

        Ok(())
    }

    fn recv_linux(&mut self) {
        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|batch| {
            let len = batch.len();
            let ret = {
                let storage = batch.chains_mut(0..len);
                let ptr = storage.as_mut_ptr() as *mut mmsghdr;
                unsafe {
                    libc::recvmmsg(
                        fd,
                        ptr,
                        len as libc::c_uint,
                        libc::MSG_DONTWAIT,
                        std::ptr::null_mut(),
                    )
                }
            };

            match ret {
                n if n > 0 => {
                    batch.complete_received_many(0..n as usize);
                }
                0 => log::warn!("recvmmsg returned 0 (unexpected)"),
                _ => {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::WouldBlock {
                        log::error!("recvmmsg failed: {err}");
                    }
                }
            }
        });
    }
}

#[cfg(target_os = "macos")]
impl Unixgram {
    fn send_macos(&mut self) -> Result<(), WriteError> {
        let fd = self.fd.as_raw_fd();

        self.tx_consumer.consume(|batch| {
            let len = batch.len();
            // Safety: No chains have been completed yet, so 0..len is valid.
            let storage = batch.chains(0..len);
            let ptr = storage.as_ptr() as *const super::socket_x::msghdr_x;

            // Debug: log each msghdr_x before sending
            for i in 0..len {
                let hdr = unsafe { &*ptr.add(i) };
                let total: usize = if !hdr.msg_iov.is_null() && hdr.msg_iovlen > 0 {
                    unsafe {
                        std::slice::from_raw_parts(hdr.msg_iov, hdr.msg_iovlen as usize)
                            .iter()
                            .map(|iov| iov.iov_len)
                            .sum()
                    }
                } else {
                    0
                };
                log::info!(
                    "sendmsg_x[{}]: iovlen={} total_bytes={} msg_datalen={} msg_flags={} msg_name={:?} msg_control={:?}",
                    i, hdr.msg_iovlen, total, hdr.msg_datalen, hdr.msg_flags, hdr.msg_name, hdr.msg_control
                );
            }

            let ret = unsafe {
                super::socket_x::sendmsg_x(
                    fd,
                    ptr,
                    len as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };

            log::info!("sendmsg_x(fd={}, cnt={}) = {}", fd, len, ret);

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                log::info!("sendmsg_x error: {:?} (raw={})", err.kind(), err.raw_os_error().unwrap_or(-1));
                match err.kind() {
                    std::io::ErrorKind::WouldBlock => {}
                    _ => {
                        log::error!("sendmsg_x failed: {err:?}");
                    }
                }
                return;
            }

            batch.finish_many(0..ret as usize);
        });

        Ok(())
    }

    fn recv_macos(&mut self) {
        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|batch| {
            log::info!("recv_macos: {} chains available", batch.len());

            let len = batch.len();
            let ret = {
                let storage = batch.chains_mut(0..len);
                let ptr = storage.as_mut_ptr() as *mut super::socket_x::msghdr_x;
                unsafe {
                    super::socket_x::recvmsg_x(fd, ptr, len as libc::c_uint, libc::MSG_DONTWAIT)
                }
            };

            log::info!("recvmsg_x(fd={}, cnt={}) = {}", fd, len, ret);

            match ret {
                n if n > 0 => {
                    batch.complete_received_many(0..n as usize);
                }
                0 => log::warn!("recvmsg_x returned 0 (unexpected)"),
                _ => {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::WouldBlock {
                        log::error!("recvmsg_x failed: {err}");
                    }
                }
            }
        });
    }
}

use libc::{
    c_char, c_int, ifreq, IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, TUN_F_CSUM, TUN_F_TSO4, TUN_F_TSO6,
    TUN_F_UFO,
};
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::sys::uio::{readv, writev};
use nix::{ioctl_write_int, ioctl_write_ptr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::{io, mem, ptr};
use utils::fd::SetNonblockingExt;
use virtio_bindings::virtio_net::{
    VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO,
};
use vm_memory::GuestMemoryMmap;

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use crate::virtio::batch_queue::{RxQueueProducer, TxQueueConsumer};
use crate::virtio::queue::Queue;
use crate::virtio::InterruptTransport;

ioctl_write_ptr!(tunsetiff, b'T', 202, c_int);
ioctl_write_int!(tunsetoffload, b'T', 208);
ioctl_write_ptr!(tunsetvnethdrsz, b'T', 216, c_int);

pub struct Tap {
    fd: OwnedFd,
    tx_consumer: TxQueueConsumer,
    rx_producer: RxQueueProducer,
}

impl Tap {
    /// Create an endpoint using the file descriptor of a tap device
    pub fn new(
        tap_name: String,
        vnet_features: u64,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Result<Self, ConnectError> {
        let fd = match open("/dev/net/tun", OFlag::O_RDWR, Mode::empty()) {
            Ok(fd) => fd,
            Err(err) => return Err(ConnectError::OpenNetTun(err)),
        };

        let mut req: ifreq = unsafe { mem::zeroed() };

        unsafe {
            ptr::copy_nonoverlapping(
                tap_name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                tap_name.len(),
            );
        }

        req.ifr_ifru.ifru_flags = IFF_TAP as i16 | IFF_NO_PI as i16 | IFF_VNET_HDR as i16;

        log::info!("Tap::new() fd={} tap={}", fd.as_raw_fd(), tap_name);

        let mut offload_flags: u64 = 0;
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_CSUM)) != 0 {
            offload_flags |= TUN_F_CSUM as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO4)) != 0 {
            offload_flags |= TUN_F_TSO4 as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO6)) != 0 {
            offload_flags |= TUN_F_TSO6 as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_UFO)) != 0 {
            offload_flags |= TUN_F_UFO as u64;
        }

        unsafe {
            if let Err(err) = tunsetiff(fd.as_raw_fd(), &mut req as *mut _ as *mut _) {
                return Err(ConnectError::TunSetIff(io::Error::from(err)));
            }

            // TODO(slp): replace hardcoded vnet size with const
            if let Err(err) = tunsetvnethdrsz(fd.as_raw_fd(), &12) {
                return Err(ConnectError::TunSetVnetHdrSz(io::Error::from(err)));
            }

            if let Err(err) = tunsetoffload(fd.as_raw_fd(), offload_flags) {
                return Err(ConnectError::TunSetOffload(io::Error::from(err)));
            }
        }

        if let Err(e) = fd.set_nonblocking(true) {
            log::warn!("Failed to set O_NONBLOCK on tap: {e}");
        }

        let tx_consumer = TxQueueConsumer::new(tx_queue, mem.clone(), interrupt.clone());
        let rx_provider = RxQueueProducer::new(rx_queue, mem, interrupt);

        Ok(Self {
            fd,
            tx_consumer,
            rx_producer: rx_provider,
        })
    }
}

impl NetBackend for Tap {
    fn send(&mut self) -> Result<(), WriteError> {
        let fd = self.fd.as_fd();

        self.tx_consumer.feed();

        // Each descriptor chain is one packet. TAP's writev combines iovecs into
        // a single packet, so we can use it directly without flattening.
        // One writev syscall per packet.
        self.tx_consumer.consume(|batch| {
            for i in 0..batch.len() {
                let chain = batch.io_slices(i);
                if chain.is_empty() {
                    continue;
                }
                match writev(fd, chain) {
                    Ok(_) => batch.finish(i),
                    Err(nix::errno::Errno::EAGAIN) => break,
                    Err(e) => {
                        log::error!("writev to tap failed: {e:?}");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        let fd = self.fd.as_fd();

        self.rx_producer.feed();

        self.rx_producer.produce(|batch| {
            for i in 0..batch.len() {
                let iovecs = batch.io_slices_mut(i);
                if iovecs.is_empty() {
                    log::warn!("Chain {i} was empty");
                    break;
                }

                match readv(fd, iovecs) {
                    Ok(n) => batch.complete(i, n),
                    Err(nix::errno::Errno::EAGAIN) => break,
                    Err(e) => {
                        log::error!("readv from tap failed: {e:?}");
                    }
                }
            }
        });

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

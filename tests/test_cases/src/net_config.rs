//! Shared network configuration utilities for guest-side network setup
//!
//! This module provides low-level network interface configuration using ioctls,
//! used by virtio-net tests to configure eth0 in the guest.

use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use std::os::fd::AsRawFd;

// Network interface configuration constants
pub const IFNAMSIZ: usize = 16;
pub const IFF_UP: nix::libc::c_short = 0x1;
pub const IFF_RUNNING: nix::libc::c_short = 0x40;

// ioctl numbers
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCSIFADDR: u64 = 0x8916;
const SIOCSIFNETMASK: u64 = 0x891c;

#[repr(C)]
#[derive(Default)]
pub struct Ifreq {
    pub ifr_name: [u8; IFNAMSIZ],
    pub ifr_ifru: IfreqIfru,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IfreqIfru {
    pub ifru_flags: nix::libc::c_short,
    pub ifru_addr: nix::libc::sockaddr,
    pub _pad: [u8; 24],
}

impl Default for IfreqIfru {
    fn default() -> Self {
        Self { _pad: [0u8; 24] }
    }
}

nix::ioctl_readwrite_bad!(ioctl_siocgifflags, SIOCGIFFLAGS, Ifreq);
nix::ioctl_readwrite_bad!(ioctl_siocsifflags, SIOCSIFFLAGS, Ifreq);
nix::ioctl_write_ptr_bad!(ioctl_siocsifaddr, SIOCSIFADDR, Ifreq);
nix::ioctl_write_ptr_bad!(ioctl_siocsifnetmask, SIOCSIFNETMASK, Ifreq);

pub fn set_interface_name(ifr: &mut Ifreq, name: &str) {
    let bytes = name.as_bytes();
    let len = bytes.len().min(IFNAMSIZ - 1);
    ifr.ifr_name[..len].copy_from_slice(&bytes[..len]);
    ifr.ifr_name[len] = 0;
}

pub fn make_sockaddr_in(ip: [u8; 4]) -> nix::libc::sockaddr {
    let mut addr: nix::libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = nix::libc::AF_INET as _;
    addr.sin_addr.s_addr = u32::from_ne_bytes(ip);
    unsafe { std::mem::transmute(addr) }
}

/// Configure a network interface with IP address and netmask, and bring it UP
pub fn configure_interface(name: &str, ip: [u8; 4], netmask: [u8; 4]) -> nix::Result<()> {
    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;
    let fd = sock.as_raw_fd();

    // Set IP address
    let mut ifr = Ifreq::default();
    set_interface_name(&mut ifr, name);
    ifr.ifr_ifru.ifru_addr = make_sockaddr_in(ip);
    unsafe { ioctl_siocsifaddr(fd, &ifr)? };

    // Set netmask
    let mut ifr = Ifreq::default();
    set_interface_name(&mut ifr, name);
    ifr.ifr_ifru.ifru_addr = make_sockaddr_in(netmask);
    unsafe { ioctl_siocsifnetmask(fd, &ifr)? };

    // Bring interface UP
    let mut ifr = Ifreq::default();
    set_interface_name(&mut ifr, name);
    unsafe { ioctl_siocgifflags(fd, &mut ifr)? };
    unsafe { ifr.ifr_ifru.ifru_flags |= IFF_UP | IFF_RUNNING };
    unsafe { ioctl_siocsifflags(fd, &mut ifr)? };

    Ok(())
}

/// Add a default route via the given gateway
pub fn add_default_route(gateway: [u8; 4]) -> nix::Result<()> {
    use nix::libc;

    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;

    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    rt.rt_dst = make_sockaddr_in([0, 0, 0, 0]);
    rt.rt_gateway = make_sockaddr_in(gateway);
    rt.rt_genmask = make_sockaddr_in([0, 0, 0, 0]);
    rt.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;

    let ret = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCADDRT as _, &rt) };
    if ret < 0 {
        return Err(nix::errno::Errno::last());
    }
    Ok(())
}

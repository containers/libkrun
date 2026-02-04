//! TAP backend for virtio-net test

use crate::{ShouldRun, TestSetup};
use krun_sys::COMPAT_NET_FEATURES;
use nix::libc;
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;

const DEFAULT_TAP_NAME: &str = "tap0";
const HOST_IP: [u8; 4] = [10, 0, 0, 1];
const NETMASK: [u8; 4] = [255, 255, 255, 0];

type KrunAddNetTapFn = unsafe extern "C" fn(
    ctx_id: u32,
    c_tap_name: *const std::ffi::c_char,
    c_mac: *mut u8,
    features: u32,
    flags: u32,
) -> i32;

fn get_krun_add_net_tap() -> Option<KrunAddNetTapFn> {
    let symbol = CString::new("krun_add_net_tap").unwrap();
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute(ptr) })
    }
}

fn interface_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{}", name)).exists()
}

// TAP device setup
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const TUNSETPERSIST: libc::c_ulong = 0x400454cb;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_VNET_HDR: libc::c_short = 0x4000;
const IFNAMSIZ: usize = 16;
const IFF_UP: libc::c_short = 0x1;
const IFF_RUNNING: libc::c_short = 0x40;

#[repr(C)]
struct Ifreq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_ifru: IfreqIfru,
}

#[repr(C)]
#[derive(Copy, Clone)]
union IfreqIfru {
    ifru_flags: libc::c_short,
    ifru_addr: libc::sockaddr,
    _pad: [u8; 24],
}

nix::ioctl_write_ptr_bad!(ioctl_tunsetiff, TUNSETIFF, Ifreq);
nix::ioctl_write_int_bad!(ioctl_tunsetpersist, TUNSETPERSIST);
nix::ioctl_readwrite_bad!(ioctl_siocsifaddr, 0x8916, Ifreq);
nix::ioctl_readwrite_bad!(ioctl_siocsifnetmask, 0x891c, Ifreq);
nix::ioctl_readwrite_bad!(ioctl_siocgifflags, 0x8913, Ifreq);
nix::ioctl_readwrite_bad!(ioctl_siocsifflags, 0x8914, Ifreq);

fn set_interface_name(ifr: &mut Ifreq, name: &str) {
    let bytes = name.as_bytes();
    let len = bytes.len().min(IFNAMSIZ - 1);
    ifr.ifr_name = [0u8; IFNAMSIZ];
    ifr.ifr_name[..len].copy_from_slice(&bytes[..len]);
}

fn make_sockaddr_in(ip: [u8; 4]) -> libc::sockaddr {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = u32::from_ne_bytes(ip);
    unsafe { std::mem::transmute(addr) }
}

fn create_tap(name: &str) -> std::io::Result<()> {
    let tun = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;
    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    set_interface_name(&mut ifr, name);
    ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
    unsafe { ioctl_tunsetiff(tun.as_raw_fd(), &ifr) }
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    unsafe { ioctl_tunsetpersist(tun.as_raw_fd(), 1) }
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}

fn configure_host_interface(name: &str, ip: [u8; 4], netmask: [u8; 4]) -> nix::Result<()> {
    let sock = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), None)?;
    let fd = sock.as_raw_fd();

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    set_interface_name(&mut ifr, name);
    ifr.ifr_ifru.ifru_addr = make_sockaddr_in(ip);
    unsafe { ioctl_siocsifaddr(fd, &mut ifr)? };

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    set_interface_name(&mut ifr, name);
    ifr.ifr_ifru.ifru_addr = make_sockaddr_in(netmask);
    unsafe { ioctl_siocsifnetmask(fd, &mut ifr)? };

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    set_interface_name(&mut ifr, name);
    unsafe { ioctl_siocgifflags(fd, &mut ifr)? };
    unsafe { ifr.ifr_ifru.ifru_flags |= IFF_UP | IFF_RUNNING };
    unsafe { ioctl_siocsifflags(fd, &mut ifr)? };

    Ok(())
}

pub fn should_run() -> ShouldRun {
    if cfg!(target_os = "macos") {
        return ShouldRun::No("TAP not supported on macOS");
    }
    if get_krun_add_net_tap().is_none() {
        return ShouldRun::No("libkrun compiled without NET");
    }
    if let Ok(tap_name) = std::env::var("LIBKRUN_TAP_NAME") {
        if !interface_exists(&tap_name) {
            return ShouldRun::No("TAP interface not found");
        }
    } else if !std::path::Path::new("/dev/net/tun").exists() {
        return ShouldRun::No("/dev/net/tun not available");
    }
    ShouldRun::Yes
}

pub fn setup_backend(ctx: u32, _test_setup: &TestSetup) -> anyhow::Result<()> {
    let tap_name = if let Ok(name) = std::env::var("LIBKRUN_TAP_NAME") {
        name
    } else {
        create_tap(DEFAULT_TAP_NAME)?;
        configure_host_interface(DEFAULT_TAP_NAME, HOST_IP, NETMASK)
            .map_err(|e| anyhow::anyhow!("Failed to configure TAP: {}", e))?;
        DEFAULT_TAP_NAME.to_string()
    };

    let mut mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
    let tap_name_c = CString::new(tap_name).unwrap();

    let net_result = unsafe {
        get_krun_add_net_tap().unwrap()(
            ctx,
            tap_name_c.as_ptr(),
            mac.as_mut_ptr(),
            COMPAT_NET_FEATURES,
            0,
        )
    };
    anyhow::ensure!(net_result >= 0, "krun_add_net_tap failed: {}", net_result);
    Ok(())
}

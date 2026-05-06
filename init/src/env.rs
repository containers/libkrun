#[cfg(target_os = "linux")]
use std::mem;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::ptr;

#[cfg(target_os = "linux")]
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};

#[cfg(target_os = "linux")]
pub fn setup_network(iface: &str) {
    let Ok(sock) = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    ) else {
        return;
    };
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let lo = c"lo";
    unsafe {
        ptr::copy_nonoverlapping(
            lo.as_ptr(),
            ifr.ifr_name.as_mut_ptr(),
            lo.to_bytes_with_nul().len(),
        );
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &ifr);
    }

    setup_dhcp(iface, sock.as_raw_fd());
}

#[cfg(not(target_os = "linux"))]
pub fn setup_network() {}

#[cfg(target_os = "linux")]
fn setup_dhcp(iface: &str, sock: i32) {
    if std::env::var("KRUN_DHCP").as_deref() != Ok("1") {
        return;
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = iface.as_bytes();
    unsafe {
        ptr::copy_nonoverlapping(
            name_bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            name_bytes.len().min(libc::IFNAMSIZ - 1),
        );
    }
    let exists = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) } == 0;
    if exists {
        unsafe {
            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr);
        }
        if let Err(e) = crate::dhcp::do_dhcp(iface) {
            eprintln!("Warning: DHCP configuration for {iface} failed: {e}");
        }
    }
}

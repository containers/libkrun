
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::mem;
#[cfg(target_os = "linux")]
use std::ptr;

#[cfg(target_os = "linux")]
pub fn setup_network(iface: &str) {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return;
    }
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let lo = b"lo\0";
    unsafe {
        ptr::copy_nonoverlapping(
            lo.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            lo.len(),
        );
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr);
    }

    #[cfg(target_os = "linux")]
    setup_dhcp(iface, sock);

    unsafe { libc::close(sock) };
}

#[cfg(not(target_os = "linux"))]
pub fn setup_network() {}

#[cfg(target_os = "linux")]
fn setup_dhcp(iface: &str, sock: i32) {
    if std::env::var("KRUN_DHCP").as_deref() != Ok("1") {
        return;
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name = CString::new(iface).unwrap();
    unsafe {
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ifr.ifr_name.as_mut_ptr(),
            name.as_bytes_with_nul().len().min(libc::IFNAMSIZ),
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

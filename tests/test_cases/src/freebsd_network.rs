#[cfg(target_os = "freebsd")]
pub fn configure_virtio_net_ip() {
    use nix::libc;
    use std::mem;

    // ioctl constants derived from freebsd-sysroot/usr/include/sys/sockio.h
    // _IOW('i', 43, struct ifaliasreq{68}) = 0x80000000 | (68<<16) | ('i'<<8) | 43
    const SIOCAIFADDR: libc::c_ulong = 0x8044692b;
    // _IOW('i', 16, struct ifreq{32}) = 0x80000000 | (32<<16) | ('i'<<8) | 16
    const SIOCSIFFLAGS: libc::c_ulong = 0x80206910;

    // Helper: convert dotted-decimal octets to a u32 in network byte order.
    // sin_addr must be in network byte order (big-endian bytes in memory).
    // On little-endian (aarch64) we must swap: .to_be() gives the right layout.
    const fn nbo(a: u8, b: u8, c: u8, d: u8) -> u32 {
        ((a as u32) << 24 | (b as u32) << 16 | (c as u32) << 8 | (d as u32)).to_be()
    }

    // FreeBSD network structures (matching freebsd-sysroot/usr/include/net/if.h)
    #[repr(C)]
    struct sockaddr_in {
        sin_len: u8,
        sin_family: u8,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [u8; 8],
    }

    #[repr(C)]
    struct ifaliasreq {
        ifra_name: [u8; 16],
        ifra_addr: sockaddr_in,
        ifra_broadaddr: sockaddr_in,
        ifra_mask: sockaddr_in,
        ifra_ifa_vhid: i32,
    }

    // Create socket
    let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sockfd < 0 {
        eprintln!("Failed to create socket");
        return;
    }

    // Interface name
    let iface_name = c"vtnet0";
    let iface_bytes = iface_name.to_bytes();

    // Build the ifaliasreq structure
    let mut ifare: ifaliasreq = unsafe { mem::zeroed() };
    ifare.ifra_name[..iface_bytes.len()].copy_from_slice(iface_bytes);

    // Set up the address structure (192.168.127.2)
    ifare.ifra_addr = sockaddr_in {
        sin_len: mem::size_of::<sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: 0,
        sin_addr: nbo(192, 168, 127, 2),
        sin_zero: [0u8; 8],
    };

    // Set up the netmask (255.255.255.0)
    ifare.ifra_mask = sockaddr_in {
        sin_len: mem::size_of::<sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: 0,
        sin_addr: nbo(255, 255, 255, 0),
        sin_zero: [0u8; 8],
    };

    // Set up the broadcast address (192.168.127.255)
    ifare.ifra_broadaddr = sockaddr_in {
        sin_len: mem::size_of::<sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: 0,
        sin_addr: nbo(192, 168, 127, 255),
        sin_zero: [0u8; 8],
    };

    // Set the interface address using ioctl
    unsafe {
        if libc::ioctl(sockfd, SIOCAIFADDR, &mut ifare as *mut _) < 0 {
            eprintln!("Failed to set IP address");
            libc::close(sockfd);
            return;
        }
    }

    // Bring the interface up
    #[repr(C)]
    struct ifreq {
        ifr_name: [u8; 16],
        ifr_union: [u8; 16],
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };
    ifr.ifr_name[..iface_bytes.len()].copy_from_slice(iface_bytes);

    // Set flags to IFF_UP
    let flags_ptr = &mut ifr.ifr_union as *mut _ as *mut u16;
    unsafe {
        *flags_ptr = libc::IFF_UP as u16;
    }

    unsafe {
        if libc::ioctl(sockfd, SIOCSIFFLAGS, &mut ifr as *mut _) < 0 {
            eprintln!("Failed to bring interface up");
            libc::close(sockfd);
            return;
        }
        libc::close(sockfd);
    }

    // Add default route via 192.168.127.1 (gvproxy gateway).
    // The rootfs has no /sbin/route binary, so we use the AF_ROUTE socket directly.
    add_default_route(nbo(192, 168, 127, 1));
}

/// Add a default route (0.0.0.0/0) via the given gateway address (already in NBO).
///
/// Sends an RTM_ADD message over an AF_ROUTE socket.  The message layout is:
///   rt_msghdr (152 bytes) + sockaddr_in dst + sockaddr_in gw + sockaddr_in netmask
#[cfg(target_os = "freebsd")]
fn add_default_route(gateway_nbo: u32) {
    use nix::libc;
    use std::mem;

    // rt_msghdr field layout from freebsd-sysroot/usr/include/net/route.h, FreeBSD 14.
    // Verified offsets:
    //   0  rtm_msglen  u16
    //   2  rtm_version u8
    //   3  rtm_type    u8
    //   4  rtm_index   u16
    //   6  _spare      u16
    //   8  rtm_flags   i32
    //  12  rtm_addrs   i32
    //  16  rtm_pid     i32  (pid_t = int on FreeBSD)
    //  20  rtm_seq     i32
    //  24  rtm_errno   i32
    //  28  rtm_fmask   i32
    //  32  rtm_inits   u64
    //  40  rtm_rmx     [u64; 14]  (struct rt_metrics, 112 bytes)
    // Total: 152 bytes
    #[repr(C)]
    struct RtMsghdr {
        rtm_msglen: u16,
        rtm_version: u8,
        rtm_type: u8,
        rtm_index: u16,
        _spare: u16,
        rtm_flags: i32,
        rtm_addrs: i32,
        rtm_pid: i32,
        rtm_seq: i32,
        rtm_errno: i32,
        rtm_fmask: i32,
        rtm_inits: u64,
        rtm_rmx: [u64; 14], // struct rt_metrics
    }

    #[repr(C)]
    struct SockaddrIn {
        sin_len: u8,
        sin_family: u8,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [u8; 8],
    }

    // RTM_ADD = 0x1, RTM_VERSION = 5
    // RTF_UP = 0x1, RTF_GATEWAY = 0x2, RTF_STATIC = 0x800
    // RTA_DST = 0x1, RTA_GATEWAY = 0x2, RTA_NETMASK = 0x4
    const RTM_ADD: u8 = 0x1;
    const RTM_VERSION: u8 = 5;
    const RTF_UP: i32 = 0x1;
    const RTF_GATEWAY: i32 = 0x2;
    const RTF_STATIC: i32 = 0x800;
    const RTA_DST: i32 = 0x1;
    const RTA_GATEWAY: i32 = 0x2;
    const RTA_NETMASK: i32 = 0x4;

    let sa_size = mem::size_of::<SockaddrIn>() as u8; // 16

    #[repr(C)]
    struct RouteMsg {
        hdr: RtMsghdr,
        dst: SockaddrIn,     // destination: 0.0.0.0 (default)
        gateway: SockaddrIn, // gateway: 192.168.127.1
        netmask: SockaddrIn, // netmask: 0.0.0.0 (default route matches all)
    }

    let msg_len = mem::size_of::<RouteMsg>() as u16;

    let msg = RouteMsg {
        hdr: RtMsghdr {
            rtm_msglen: msg_len,
            rtm_version: RTM_VERSION,
            rtm_type: RTM_ADD,
            rtm_index: 0,
            _spare: 0,
            rtm_flags: RTF_UP | RTF_GATEWAY | RTF_STATIC,
            rtm_addrs: RTA_DST | RTA_GATEWAY | RTA_NETMASK,
            rtm_pid: 0,
            rtm_seq: 1,
            rtm_errno: 0,
            rtm_fmask: 0,
            rtm_inits: 0,
            rtm_rmx: [0u64; 14],
        },
        dst: SockaddrIn {
            sin_len: mem::size_of::<SockaddrIn>() as u8,
            sin_family: libc::AF_INET as u8,
            sin_port: 0,
            sin_addr: 0, // 0.0.0.0
            sin_zero: [0u8; 8],
        },
        gateway: SockaddrIn {
            sin_len: sa_size,
            sin_family: libc::AF_INET as u8,
            sin_port: 0,
            sin_addr: gateway_nbo,
            sin_zero: [0u8; 8],
        },
        netmask: SockaddrIn {
            sin_len: sa_size,
            sin_family: libc::AF_INET as u8,
            sin_port: 0,
            sin_addr: 0, // 0.0.0.0 mask = default route
            sin_zero: [0u8; 8],
        },
    };

    unsafe {
        let sockfd = libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, 0);
        if sockfd < 0 {
            eprintln!("Failed to open AF_ROUTE socket");
            return;
        }

        let ret = libc::write(
            sockfd,
            &msg as *const _ as *const libc::c_void,
            mem::size_of::<RouteMsg>(),
        );
        if ret < 0 {
            eprintln!("Failed to add default route");
        }

        libc::close(sockfd);
    }
}

#[cfg(not(target_os = "freebsd"))]
pub fn configure_virtio_net_ip() {
    // No-op on non-FreeBSD systems
}

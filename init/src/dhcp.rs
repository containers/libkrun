use anyhow::{bail, Context};
use std::io::Error as IoError;
use std::mem;
use std::slice;

const DHCP_BUFFER_SIZE: usize = 576;
const DHCP_OPTIONS_SIZE: usize = 60;
const DHCP_OPTIONS_OFFSET: usize = 240;
const DHCP_OPTIONS_END: u8 = 0xff;
const DHCP_MSG_OFFER: u8 = 2;
const DHCP_MSG_ACK: u8 = 5;

#[repr(C, packed)]
struct DhcpPacket {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: u32,
    yiaddr: u32,
    siaddr: u32,
    giaddr: u32,
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    magic: u32,
    options: [u8; DHCP_OPTIONS_SIZE],
}

impl DhcpPacket {
    fn zeroed() -> Self {
        // SAFETY: DhcpPacket is plain-old-data with no padding invariants.
        unsafe { mem::zeroed() }
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: packed repr, no padding; reading as bytes is valid.
        unsafe { slice::from_raw_parts(self as *const _ as *const u8, mem::size_of::<Self>()) }
    }
}

struct DhcpOptionsWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> DhcpOptionsWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn push(&mut self, code: u8, data: &[u8]) {
        self.buf[self.pos] = code;
        self.buf[self.pos + 1] = data.len() as u8;
        self.buf[self.pos + 2..self.pos + 2 + data.len()].copy_from_slice(data);
        self.pos += 2 + data.len();
    }

    fn finish(self) {
        self.buf[self.pos] = DHCP_OPTIONS_END;
    }
}

struct DhcpOptions<'a>(&'a [u8]);

impl<'a> Iterator for DhcpOptions<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let opt = *self.0.first()?;
            if opt == DHCP_OPTIONS_END {
                self.0 = &[];
                return None;
            }
            self.0 = &self.0[1..];
            if opt == 0 {
                continue;
            }
            let len = *self.0.first()? as usize;
            self.0 = &self.0[1..];
            let data = self.0.get(..len)?;
            self.0 = &self.0[len..];
            return Some((opt, data));
        }
    }
}

// libc doesn't expose ifinfomsg, ifaddrmsg, or rtmsg — define them locally.

#[repr(C)]
struct IfInfoMsg {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[repr(C)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

unsafe fn struct_as_bytes<T: Sized>(v: &T) -> &[u8] {
    slice::from_raw_parts(v as *const T as *const u8, mem::size_of::<T>())
}

fn nl_send(sock: libc::c_int, buf: &[u8]) -> anyhow::Result<()> {
    // Use mem::zeroed() so the opaque nl_pad field is correctly initialised.
    let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;

    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut _,
        iov_len: buf.len(),
    };
    // Use zeroed() rather than a struct literal: musl's msghdr has private
    // padding fields (__pad1, __pad2) that cannot be named in a literal.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &sa as *const _ as *mut _;
    msg.msg_namelen = mem::size_of_val(&sa) as u32;
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    let ret = unsafe { libc::sendmsg(sock, &msg, 0) };
    if ret < 0 {
        bail!("nl_send: {}", IoError::last_os_error());
    }
    Ok(())
}

fn nl_recv(sock: libc::c_int, buf: &mut [u8]) -> anyhow::Result<usize> {
    let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    let iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &mut sa as *mut _ as *mut _;
    msg.msg_namelen = mem::size_of_val(&sa) as u32;
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    let ret = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if ret < 0 {
        bail!("nl_recv: {}", IoError::last_os_error());
    }
    Ok(ret as usize)
}

fn add_rtattr(buf: &mut [u8], msg_len: &mut usize, rta_type: u16, data: &[u8]) {
    let rta_len = (4 + data.len()) as u16;
    let aligned_start = (*msg_len + 3) & !3;
    let end = aligned_start + ((rta_len as usize + 3) & !3);
    assert!(end <= buf.len(), "netlink buffer too small");

    buf[aligned_start..aligned_start + 2].copy_from_slice(&rta_len.to_ne_bytes());
    buf[aligned_start + 2..aligned_start + 4].copy_from_slice(&rta_type.to_ne_bytes());
    buf[aligned_start + 4..aligned_start + 4 + data.len()].copy_from_slice(data);
    buf[aligned_start + 4 + data.len()..end].fill(0);

    *msg_len = end;
    buf[0..4].copy_from_slice(&(*msg_len as u32).to_ne_bytes());
}

fn nl_check_ack(buf: &[u8], recv_len: usize, op: &str) -> anyhow::Result<()> {
    let min = mem::size_of::<libc::nlmsghdr>() + mem::size_of::<libc::nlmsgerr>();
    if recv_len < min {
        bail!("{op}: netlink response too short");
    }
    let nlh = unsafe { &*(buf.as_ptr() as *const libc::nlmsghdr) };
    if nlh.nlmsg_type != libc::NLMSG_ERROR as u16 {
        bail!(
            "{op}: expected NLMSG_ERROR ACK, got type {}",
            nlh.nlmsg_type
        );
    }
    let err_offset = mem::size_of::<libc::nlmsghdr>();
    let err = i32::from_ne_bytes(buf[err_offset..err_offset + 4].try_into().unwrap());
    if err != 0 {
        bail!("{op}: netlink error {err}");
    }
    Ok(())
}

fn nl_hdr(buf: &mut [u8], msg_len: usize, nlmsg_type: u16, flags: u16) {
    let nlh = libc::nlmsghdr {
        nlmsg_len: msg_len as u32,
        nlmsg_type,
        nlmsg_flags: flags,
        nlmsg_seq: 1,
        nlmsg_pid: unsafe { libc::getpid() } as u32,
    };
    buf[..mem::size_of_val(&nlh)].copy_from_slice(unsafe { struct_as_bytes(&nlh) });
}

fn set_mtu(nl_sock: libc::c_int, iface_index: i32, mtu: u32) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    let base = mem::size_of::<libc::nlmsghdr>() + mem::size_of::<IfInfoMsg>();
    let mut msg_len = base;

    nl_hdr(
        &mut buf,
        base,
        libc::RTM_NEWLINK,
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
    );

    let ifi = IfInfoMsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: libc::ARPHRD_ETHER,
        ifi_index: iface_index,
        ifi_flags: 0,
        ifi_change: 0,
    };
    let ifi_off = mem::size_of::<libc::nlmsghdr>();
    buf[ifi_off..ifi_off + mem::size_of_val(&ifi)]
        .copy_from_slice(unsafe { struct_as_bytes(&ifi) });

    add_rtattr(&mut buf, &mut msg_len, libc::IFLA_MTU, &mtu.to_ne_bytes());

    nl_send(nl_sock, &buf[..msg_len])?;
    let recv_len = nl_recv(nl_sock, &mut buf)?;
    nl_check_ack(&buf, recv_len, "set_mtu")
}

fn mod_addr4(
    nl_sock: libc::c_int,
    iface_index: i32,
    cmd: u16,
    addr: u32,
    prefix_len: u8,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    let base = mem::size_of::<libc::nlmsghdr>() + mem::size_of::<IfAddrMsg>();
    let mut msg_len = base;

    nl_hdr(
        &mut buf,
        base,
        cmd,
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16,
    );

    let ifa = IfAddrMsg {
        ifa_family: libc::AF_INET as u8,
        ifa_prefixlen: prefix_len,
        ifa_flags: 0,
        ifa_scope: libc::RT_SCOPE_UNIVERSE,
        ifa_index: iface_index as u32,
    };
    let ifa_off = mem::size_of::<libc::nlmsghdr>();
    buf[ifa_off..ifa_off + mem::size_of_val(&ifa)]
        .copy_from_slice(unsafe { struct_as_bytes(&ifa) });

    let addr_bytes = addr.to_ne_bytes();
    add_rtattr(&mut buf, &mut msg_len, libc::IFA_LOCAL, &addr_bytes);
    add_rtattr(&mut buf, &mut msg_len, libc::IFA_ADDRESS, &addr_bytes);

    nl_send(nl_sock, &buf[..msg_len])?;
    let recv_len = nl_recv(nl_sock, &mut buf)?;
    nl_check_ack(&buf, recv_len, "mod_addr4")
}

fn mod_route4(
    nl_sock: libc::c_int,
    iface_index: i32,
    cmd: u16,
    gateway: u32,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    let base = mem::size_of::<libc::nlmsghdr>() + mem::size_of::<RtMsg>();
    let mut msg_len = base;

    nl_hdr(
        &mut buf,
        base,
        cmd,
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16,
    );

    let rtm = RtMsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: libc::RT_TABLE_MAIN,
        rtm_protocol: libc::RTPROT_BOOT,
        rtm_scope: libc::RT_SCOPE_UNIVERSE,
        rtm_type: libc::RTN_UNICAST,
        rtm_flags: 0,
    };
    let rtm_off = mem::size_of::<libc::nlmsghdr>();
    buf[rtm_off..rtm_off + mem::size_of_val(&rtm)]
        .copy_from_slice(unsafe { struct_as_bytes(&rtm) });

    add_rtattr(
        &mut buf,
        &mut msg_len,
        libc::RTA_OIF,
        &(iface_index as u32).to_ne_bytes(),
    );
    add_rtattr(&mut buf, &mut msg_len, libc::RTA_DST, &0u32.to_ne_bytes());
    add_rtattr(
        &mut buf,
        &mut msg_len,
        libc::RTA_GATEWAY,
        &gateway.to_ne_bytes(),
    );

    nl_send(nl_sock, &buf[..msg_len])?;
    let recv_len = nl_recv(nl_sock, &mut buf)?;
    nl_check_ack(&buf, recv_len, "mod_route4")
}

fn dhcp_msg_type(response: &[u8]) -> u8 {
    DhcpOptions(response.get(DHCP_OPTIONS_OFFSET..).unwrap_or(&[]))
        .find(|&(code, _)| code == 53)
        .and_then(|(_, data)| data.first().copied())
        .unwrap_or(0)
}

fn handle_dhcp_ack(nl_sock: libc::c_int, iface_index: i32, response: &[u8]) -> anyhow::Result<()> {
    if response.len() < DHCP_OPTIONS_OFFSET + 1 {
        bail!("DHCPACK too short ({} bytes)", response.len());
    }

    let addr = u32::from_ne_bytes(response[16..20].try_into().unwrap());
    if addr == 0 {
        bail!("DHCPACK: yiaddr is 0.0.0.0");
    }

    let mut netmask: u32 = 0;
    let mut router: u32 = 0;
    let mut mtu: u16 = 65520;
    let mut resolv_conf = String::new();

    for (opt, data) in DhcpOptions(response.get(DHCP_OPTIONS_OFFSET..).unwrap_or(&[])) {
        match opt {
            1 if data.len() >= 4 => {
                netmask = u32::from_ne_bytes(data[..4].try_into().unwrap());
            }
            3 if data.len() >= 4 => {
                router = u32::from_ne_bytes(data[..4].try_into().unwrap());
            }
            6 => {
                for chunk in data.chunks_exact(4) {
                    resolv_conf.push_str(&format!(
                        "nameserver {}.{}.{}.{}\n",
                        chunk[0], chunk[1], chunk[2], chunk[3]
                    ));
                }
            }
            26 if data.len() >= 2 => {
                mtu = u16::from_be_bytes(data[..2].try_into().unwrap()).clamp(1280, 65520);
            }
            _ => {}
        }
    }

    if !resolv_conf.is_empty() {
        if let Err(e) = std::fs::write("/etc/resolv.conf", &resolv_conf) {
            eprintln!("Warning: couldn't write /etc/resolv.conf: {e}");
        }
    }

    let prefix_len = u32::from_be(netmask).leading_ones() as u8;

    mod_addr4(nl_sock, iface_index, libc::RTM_NEWADDR, addr, prefix_len)
        .context("add address from DHCP")?;
    mod_route4(nl_sock, iface_index, libc::RTM_NEWROUTE, router)
        .context("add default route from DHCP")?;
    let _ = set_mtu(nl_sock, iface_index, mtu as u32);

    Ok(())
}

fn scopeguard<F: FnOnce()>(f: F) -> impl Drop {
    struct Guard<F: FnOnce()>(Option<F>);
    impl<F: FnOnce()> Drop for Guard<F> {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                f();
            }
        }
    }
    Guard(Some(f))
}

pub fn do_dhcp(iface: &str) -> anyhow::Result<()> {
    let iface_cstr = std::ffi::CString::new(iface).unwrap();

    let iface_index = unsafe { libc::if_nametoindex(iface_cstr.as_ptr()) } as i32;
    if iface_index == 0 {
        bail!("if_nametoindex({iface}): {}", IoError::last_os_error());
    }

    let nl_sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if nl_sock < 0 {
        bail!("socket(AF_NETLINK): {}", IoError::last_os_error());
    }
    let _nl_guard = scopeguard(move || unsafe {
        libc::close(nl_sock);
    });

    let mut nl_sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
    nl_sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    nl_sa.nl_pid = unsafe { libc::getpid() } as u32;
    if unsafe {
        libc::bind(
            nl_sock,
            &nl_sa as *const _ as *const libc::sockaddr,
            mem::size_of_val(&nl_sa) as u32,
        )
    } < 0
    {
        bail!("bind(netlink): {}", IoError::last_os_error());
    }

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if sock < 0 {
        bail!("socket(AF_INET): {}", IoError::last_os_error());
    }
    let _sock_guard = scopeguard(move || unsafe {
        libc::close(sock);
    });

    let bcast: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            &bcast as *const _ as *const _,
            mem::size_of_val(&bcast) as u32,
        );
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_cstr.as_ptr() as *const _,
            (iface.len() + 1) as u32,
        );
    }

    let mut bind_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    bind_addr.sin_family = libc::AF_INET as libc::sa_family_t;
    bind_addr.sin_port = 68u16.to_be();
    if unsafe {
        libc::bind(
            sock,
            &bind_addr as *const _ as *const libc::sockaddr,
            mem::size_of_val(&bind_addr) as u32,
        )
    } < 0
    {
        bail!("bind(UDP 68): {}", IoError::last_os_error());
    }

    let mut pkt = DhcpPacket::zeroed();
    pkt.op = 1;
    pkt.htype = 1;
    pkt.hlen = 6;
    pkt.xid = (unsafe { libc::getpid() } as u32).to_be();
    pkt.flags = 0x8000u16.to_be();
    pkt.magic = 0x63825363u32.to_be();

    let mut mac_ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = iface.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr() as *const libc::c_char,
            mac_ifr.ifr_name.as_mut_ptr(),
            name_bytes.len().min(libc::IFNAMSIZ - 1),
        );
    }
    if unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR as _, &mut mac_ifr) } < 0 {
        bail!("ioctl(SIOCGIFHWADDR): {}", IoError::last_os_error());
    }
    let sa_data = unsafe { mac_ifr.ifr_ifru.ifru_hwaddr.sa_data };
    for (dst, src) in pkt.chaddr.iter_mut().zip(sa_data.iter().take(6)) {
        // We need to allow the unnecessary cast, because this will cause clippy to fail on aarch64
        // without it
        #[allow(clippy::unnecessary_cast)]
        {
            *dst = *src as u8;
        }
    }

    let mut opts = DhcpOptionsWriter::new(&mut pkt.options);
    opts.push(53, &[1]); // Discover
    opts.push(80, &[]); // Rapid Commit
    opts.finish();

    let mut dest: libc::sockaddr_in = unsafe { mem::zeroed() };
    dest.sin_family = libc::AF_INET as libc::sa_family_t;
    dest.sin_port = 67u16.to_be();
    dest.sin_addr.s_addr = libc::INADDR_BROADCAST;

    let mut timeout: libc::timeval = unsafe { mem::zeroed() };
    timeout.tv_usec = 100_000;
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const _,
            mem::size_of_val(&timeout) as u32,
        );
    }

    let pkt_bytes = pkt.as_bytes();
    if unsafe {
        libc::sendto(
            sock,
            pkt_bytes.as_ptr() as *const _,
            pkt_bytes.len(),
            0,
            &dest as *const _ as *const libc::sockaddr,
            mem::size_of_val(&dest) as u32,
        )
    } < 0
    {
        bail!("sendto(DISCOVER): {}", IoError::last_os_error());
    }

    let mut response = [0u8; DHCP_BUFFER_SIZE];
    let mut from: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut from_len = mem::size_of_val(&from) as u32;
    let recv_len = unsafe {
        libc::recvfrom(
            sock,
            response.as_mut_ptr() as *mut _,
            response.len(),
            0,
            &mut from as *mut _ as *mut libc::sockaddr,
            &mut from_len,
        )
    };

    if recv_len <= 0 {
        return Ok(()); // no response — VM may be IPv6-only
    }
    let recv_len = recv_len as usize;
    let msg_type = dhcp_msg_type(&response[..recv_len]);

    if msg_type == DHCP_MSG_ACK {
        handle_dhcp_ack(nl_sock, iface_index, &response[..recv_len])?;
    } else if msg_type == DHCP_MSG_OFFER {
        let offered_addr = u32::from_ne_bytes(response[16..20].try_into().unwrap());
        let server_addr = from.sin_addr.s_addr;

        pkt.options = [0; DHCP_OPTIONS_SIZE];
        let mut opts = DhcpOptionsWriter::new(&mut pkt.options);
        opts.push(53, &[3]); // Request
        opts.push(50, &offered_addr.to_ne_bytes()); // Requested IP
        opts.push(54, &server_addr.to_ne_bytes()); // Server ID
        opts.finish();

        let pkt_bytes = pkt.as_bytes();
        if unsafe {
            libc::sendto(
                sock,
                pkt_bytes.as_ptr() as *const _,
                pkt_bytes.len(),
                0,
                &dest as *const _ as *const libc::sockaddr,
                mem::size_of_val(&dest) as u32,
            )
        } < 0
        {
            bail!("sendto(REQUEST): {}", IoError::last_os_error());
        }

        from_len = mem::size_of_val(&from) as u32;
        let recv_len2 = unsafe {
            libc::recvfrom(
                sock,
                response.as_mut_ptr() as *mut _,
                response.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut from_len,
            )
        };
        if recv_len2 <= 0 {
            bail!("no DHCPACK received");
        }
        let recv_len2 = recv_len2 as usize;
        let ack_type = dhcp_msg_type(&response[..recv_len2]);
        if ack_type != DHCP_MSG_ACK {
            bail!("expected DHCPACK, got type {ack_type}");
        }
        handle_dhcp_ack(nl_sock, iface_index, &response[..recv_len2])?;
    } else {
        bail!("unexpected DHCP message type {msg_type}");
    }

    Ok(())
}

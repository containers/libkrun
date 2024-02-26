use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{
    bind, connect, getpeername, recv, send, sendto, socket, AddressFamily, MsgFlags, SockFlag,
    SockType, SockaddrIn,
};
use nix::unistd::close;

#[cfg(target_os = "macos")]
use super::super::linux_errno::linux_errno_raw;
use super::super::Queue as VirtQueue;
use super::defs;
use super::defs::uapi;
use super::muxer::{push_packet, MuxerRx};
use super::muxer_rxq::MuxerRxQ;
use super::packet::{
    TsiAcceptReq, TsiConnectReq, TsiGetnameRsp, TsiListenReq, TsiSendtoAddr, VsockPacket,
};
use super::proxy::{Proxy, ProxyError, ProxyRemoval, ProxyStatus, ProxyUpdate, RecvPkt};
use utils::epoll::EventSet;

use vm_memory::GuestMemoryMmap;

pub struct UdpProxy {
    pub id: u64,
    cid: u64,
    local_port: u32,
    peer_port: u32,
    fd: RawFd,
    pub status: ProxyStatus,
    sendto_addr: Option<SockaddrIn>,
    listening: bool,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    rx_cnt: Wrapping<u32>,
    tx_cnt: Wrapping<u32>,
    peer_buf_alloc: u32,
    peer_fwd_cnt: Wrapping<u32>,
}

impl UdpProxy {
    pub fn new(
        id: u64,
        cid: u64,
        peer_port: u32,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
    ) -> Result<Self, ProxyError> {
        let fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(ProxyError::CreatingSocket)?;

        // macOS forces us to do this here instead of just using SockFlag::SOCK_NONBLOCK above.
        match fcntl(fd, FcntlArg::F_GETFL) {
            Ok(flags) => match OFlag::from_bits(flags) {
                Some(flags) => {
                    if let Err(e) = fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                        warn!("error switching to non-blocking: id={}, err={}", id, e);
                    }
                }
                None => error!("invalid fd flags id={}", id),
            },
            Err(e) => error!("couldn't obtain fd flags id={}, err={}", id, e),
        };

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

        Ok(UdpProxy {
            id,
            cid,
            local_port: 0,
            peer_port,
            fd,
            status: ProxyStatus::Idle,
            sendto_addr: None,
            listening: false,
            mem,
            queue,
            rxq,
            rx_cnt: Wrapping(0),
            tx_cnt: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
        })
    }

    fn init_pkt(&self, pkt: &mut VsockPacket) {
        debug!(
            "udp: init_pkt: id={}, src_port={}, dst_port={}",
            self.id, self.local_port, self.peer_port
        );
        pkt.set_op(uapi::VSOCK_OP_RW)
            .set_src_cid(self.cid)
            .set_dst_cid(uapi::VSOCK_HOST_CID)
            .set_dst_port(self.peer_port)
            .set_src_port(0)
            .set_type(uapi::VSOCK_TYPE_DGRAM)
            .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
            .set_fwd_cnt(self.tx_cnt.0);
    }

    /*
    fn peer_avail_credit(&self) -> usize {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0 as usize
    }

    fn send_credit_request(&self) {
        // This response goes to the connection.
        let rx = MuxerRx::CreditRequest {
            local_port: self.local_port,
            peer_port: self.peer_port,
            fwd_cnt: self.tx_cnt.0,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }
    */

    fn recv_to_pkt(&self, pkt: &mut VsockPacket) -> RecvPkt {
        if let Some(buf) = pkt.buf_mut() {
            // Disable UDP credit accounting until is fixed in the kernel
            //let peer_credit = self.peer_avail_credit();
            //let max_len = std::cmp::min(buf.len(), peer_credit);
            let max_len = buf.len();

            /*
            debug!(
                "recv_to_pkt: peer_avail_credit={}, buf.len={}, max_len={}",
                self.peer_avail_credit(),
                buf.len(),
                max_len,
            );

            if max_len == 0 {
                return RecvPkt::WaitForCredit;
            }
            */

            match recv(self.fd, &mut buf[..max_len], MsgFlags::empty()) {
                Ok(cnt) => {
                    debug!("vsock: udp: recv cnt={}", cnt);
                    if cnt > 0 {
                        RecvPkt::Read(cnt)
                    } else {
                        RecvPkt::Close
                    }
                }
                Err(e) => {
                    debug!("vsock: udp: recv_pkt: recv error: {:?}", e);
                    RecvPkt::Error
                }
            }
        } else {
            debug!("vsock: udp: recv_pkt: pkt without buf");
            RecvPkt::Error
        }
    }

    fn recv_pkt(&mut self) -> (bool, bool) {
        let mut have_used = false;
        let mut wait_credit = false;
        let mut queue = self.queue.lock().unwrap();

        while let Some(head) = queue.pop(&self.mem) {
            let len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => match self.recv_to_pkt(&mut pkt) {
                    RecvPkt::WaitForCredit => {
                        wait_credit = true;
                        0
                    }
                    RecvPkt::Read(cnt) => {
                        self.rx_cnt += Wrapping(cnt as u32);
                        self.init_pkt(&mut pkt);
                        pkt.set_len(cnt as u32);
                        pkt.hdr().len() + cnt
                    }
                    RecvPkt::Close => {
                        self.status = ProxyStatus::Closed;
                        0
                    }
                    RecvPkt::Error => 0,
                },
                Err(e) => {
                    debug!("vsock: tcp: recv_pkt: RX queue error: {:?}", e);
                    0
                }
            };

            if len == 0 {
                queue.undo_pop();
                break;
            } else {
                have_used = true;
                debug!("vsock: udp: recv_pkt: pushing packet with {} bytes", len);
                if let Err(e) = queue.add_used(&self.mem, head.index, len as u32) {
                    error!("failed to add used elements to the queue: {:?}", e);
                }
            }
        }

        debug!("vsock: udp: recv_pkt: have_used={}", have_used);
        (have_used, wait_credit)
    }
}

impl Proxy for UdpProxy {
    fn id(&self) -> u64 {
        self.id
    }

    fn status(&self) -> ProxyStatus {
        self.status
    }

    fn connect(&mut self, pkt: &VsockPacket, req: TsiConnectReq) -> ProxyUpdate {
        debug!("vsock: udp: connect: addr={}, port={}", req.addr, req.port);
        let res = match connect(
            self.fd,
            &SockaddrIn::from(SocketAddrV4::new(req.addr, req.port)),
        ) {
            Ok(()) => {
                debug!("vsock: connect: Connected");
                self.status = ProxyStatus::Connected;
                0
            }
            Err(e) => {
                debug!("vsock: UdpProxy: Error connecting: {}", e);
                #[cfg(target_os = "macos")]
                let errno = -linux_errno_raw(e as i32);
                #[cfg(target_os = "linux")]
                let errno = -(e as i32);
                errno
            }
        };

        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        // This response goes to the connection.
        let rx = MuxerRx::ConnResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            result: res,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);

        let mut update = ProxyUpdate::default();
        if res == 0 && !self.listening {
            update.polling = Some((self.id, self.fd, EventSet::IN));
        }
        update
    }

    fn getpeername(&mut self, pkt: &VsockPacket) {
        debug!("vsock: udp: process_getpeername");

        let name = getpeername::<SockaddrIn>(self.fd).unwrap();
        let addr = Ipv4Addr::from(name.ip());
        let data = TsiGetnameRsp {
            addr,
            port: name.port(),
            result: 0,
        };

        // This response goes to the connection.
        let rx = MuxerRx::GetnameResponse {
            local_port: pkt.dst_port(),
            peer_port: pkt.src_port(),
            data,
        };
        push_packet(self.cid, rx, &self.rxq, &self.queue, &self.mem);
    }

    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        debug!("vsock: udp_proxy: sendmsg");

        let ret = if let Some(buf) = pkt.buf() {
            #[cfg(target_os = "macos")]
            let flags = MsgFlags::empty();
            #[cfg(target_os = "linux")]
            let flags = MsgFlags::MSG_NOSIGNAL;

            match send(self.fd, buf, flags) {
                Ok(sent) => {
                    self.tx_cnt += Wrapping(sent as u32);
                    sent as i32
                }
                Err(err) => -(err as i32),
            }
        } else {
            -libc::EINVAL
        };

        debug!("vsock: udp_proxy: sendmsg ret={}", ret);

        ProxyUpdate::default()
    }

    fn sendto_addr(&mut self, req: TsiSendtoAddr) -> ProxyUpdate {
        debug!(
            "vsock: udp_proxy: sendto_addr: addr={}, port={}",
            req.addr, req.port
        );

        let mut update = ProxyUpdate::default();

        self.sendto_addr = Some(SockaddrIn::from(SocketAddrV4::new(req.addr, req.port)));
        if !self.listening {
            match bind(self.fd, &SockaddrIn::new(0, 0, 0, 0, 0)) {
                Ok(_) => {
                    self.listening = true;
                    update.polling = Some((self.id, self.fd, EventSet::IN));
                }
                Err(e) => debug!("vsock: udp_proxy: couldn't bind socket: {}", e),
            }
        }

        update
    }

    fn sendto_data(&mut self, pkt: &VsockPacket) {
        debug!("vsock: udp_proxy: sendto_data");

        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        if let Some(addr) = self.sendto_addr {
            if let Some(buf) = pkt.buf() {
                #[cfg(target_os = "macos")]
                let flags = MsgFlags::empty();
                #[cfg(target_os = "linux")]
                let flags = MsgFlags::MSG_NOSIGNAL;

                match sendto(self.fd, buf, &addr, flags) {
                    Ok(sent) => {
                        self.tx_cnt += Wrapping(sent as u32);
                    }
                    Err(err) => debug!("error in sendto: {}", err),
                }
            } else {
                debug!("vsock: udp_proxy: sendto_data pkt without buffer");
            }
        } else {
            debug!("vsock: udp_proxy: sendto_data without sendto_addr");
        }
    }

    fn listen(
        &mut self,
        _pkt: &VsockPacket,
        _req: TsiListenReq,
        _host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn accept(&mut self, _req: TsiAcceptReq) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate {
        debug!(
            "vsock: udp_proxy: update_credit: buf_alloc={} rx_cnt={} fwd_cnt={}",
            pkt.buf_alloc(),
            self.rx_cnt,
            pkt.fwd_cnt()
        );
        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        ProxyUpdate {
            polling: Some((self.id, self.fd, EventSet::IN)),
            ..Default::default()
        }
    }

    fn process_op_response(&mut self, _pkt: &VsockPacket) -> ProxyUpdate {
        ProxyUpdate::default()
    }

    fn release(&mut self) -> ProxyUpdate {
        debug!("release");
        let remove_proxy = if self.status == ProxyStatus::Listening {
            ProxyRemoval::Immediate
        } else {
            ProxyRemoval::Deferred
        };
        ProxyUpdate {
            remove_proxy,
            ..Default::default()
        }
    }

    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate {
        let mut update = ProxyUpdate::default();

        if evset.contains(EventSet::HANG_UP) {
            update.remove_proxy = if self.status == ProxyStatus::Listening {
                ProxyRemoval::Immediate
            } else {
                ProxyRemoval::Deferred
            };
            return update;
        }

        if evset.contains(EventSet::IN) {
            let (signal_queue, wait_credit) = self.recv_pkt();
            update.signal_queue = signal_queue || wait_credit;

            if wait_credit && self.status != ProxyStatus::WaitingCreditUpdate {
                self.status = ProxyStatus::WaitingCreditUpdate;
                let rx = MuxerRx::CreditRequest {
                    local_port: self.local_port,
                    peer_port: self.peer_port,
                    fwd_cnt: self.tx_cnt.0,
                };
                update.push_credit_req = Some(rx);
            }

            if self.status == ProxyStatus::WaitingCreditUpdate {
                debug!("process_event: WaitingCreditUpdate");
                update.polling = Some((self.id(), self.fd, EventSet::empty()));
            }
        }

        if evset.contains(EventSet::OUT) {
            error!("vsock::udp: EventSet::OUT unexpected");
        }

        update
    }
}

impl AsRawFd for UdpProxy {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for UdpProxy {
    fn drop(&mut self) {
        if let Err(e) = close(self.fd) {
            warn!("error closing proxy fd: {}", e);
        }
    }
}

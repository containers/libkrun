use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use super::super::super::legacy::Gic;
use super::super::Queue as VirtQueue;
use super::super::VIRTIO_MMIO_INT_VRING;
use super::defs;
use super::defs::uapi;
use super::muxer_rxq::{rx_to_pkt, MuxerRxQ};
use super::muxer_thread::MuxerThread;
use super::packet::{TsiConnectReq, TsiGetnameRsp, VsockPacket};
use super::proxy::{Proxy, ProxyRemoval, ProxyUpdate};
use super::reaper::ReaperThread;
use super::tcp::TcpProxy;
#[cfg(target_os = "macos")]
use super::timesync::TimesyncThread;
use super::udp::UdpProxy;
use super::unix::UnixProxy;
use super::VsockError;
use crossbeam_channel::{unbounded, Sender};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use std::net::Ipv4Addr;

pub type ProxyMap = Arc<RwLock<HashMap<u64, Mutex<Box<dyn Proxy>>>>>;

/// A muxer RX queue item.
#[derive(Debug)]
pub enum MuxerRx {
    Reset {
        local_port: u32,
        peer_port: u32,
    },
    GetnameResponse {
        local_port: u32,
        peer_port: u32,
        data: TsiGetnameRsp,
    },
    ConnResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    OpRequest {
        local_port: u32,
        peer_port: u32,
    },
    OpResponse {
        local_port: u32,
        peer_port: u32,
    },
    CreditRequest {
        local_port: u32,
        peer_port: u32,
        fwd_cnt: u32,
    },
    CreditUpdate {
        local_port: u32,
        peer_port: u32,
        fwd_cnt: u32,
    },
    ListenResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
    AcceptResponse {
        local_port: u32,
        peer_port: u32,
        result: i32,
    },
}

pub fn push_packet(
    cid: u64,
    rx: MuxerRx,
    rxq_mutex: &Arc<Mutex<MuxerRxQ>>,
    queue_mutex: &Arc<Mutex<VirtQueue>>,
    mem: &GuestMemoryMmap,
) {
    let mut queue = queue_mutex.lock().unwrap();
    if let Some(head) = queue.pop(mem) {
        if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
            rx_to_pkt(cid, rx, &mut pkt);
            if let Err(e) = queue.add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len()) {
                error!("failed to add used elements to the queue: {:?}", e);
            }
        }
    } else {
        error!("couldn't push pkt to queue, adding it to rxq");
        drop(queue);
        rxq_mutex.lock().unwrap().push(rx);
    }
}

pub struct VsockMuxer {
    cid: u64,
    host_port_map: Option<HashMap<u16, u16>>,
    queue: Option<Arc<Mutex<VirtQueue>>>,
    mem: Option<GuestMemoryMmap>,
    rxq: Arc<Mutex<MuxerRxQ>>,
    epoll: Epoll,
    interrupt_evt: EventFd,
    interrupt_status: Arc<AtomicUsize>,
    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
    proxy_map: ProxyMap,
    reaper_sender: Option<Sender<u64>>,
    unix_ipc_port_map: Option<HashMap<u32, PathBuf>>,
}

impl VsockMuxer {
    pub(crate) fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        interrupt_evt: EventFd,
        interrupt_status: Arc<AtomicUsize>,
        unix_ipc_port_map: Option<HashMap<u32, PathBuf>>,
    ) -> Self {
        VsockMuxer {
            cid,
            host_port_map,
            queue: None,
            mem: None,
            rxq: Arc::new(Mutex::new(MuxerRxQ::new())),
            epoll: Epoll::new().unwrap(),
            interrupt_evt,
            interrupt_status,
            intc: None,
            irq_line: None,
            proxy_map: Arc::new(RwLock::new(HashMap::new())),
            reaper_sender: None,
            unix_ipc_port_map,
        }
    }

    pub(crate) fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        intc: Option<Arc<Mutex<Gic>>>,
        irq_line: Option<u32>,
    ) {
        self.queue = Some(queue.clone());
        self.mem = Some(mem.clone());
        self.intc.clone_from(&intc);
        self.irq_line = irq_line;

        #[cfg(target_os = "macos")]
        {
            let timesync = TimesyncThread::new(
                self.cid,
                mem.clone(),
                queue.clone(),
                self.interrupt_evt.try_clone().unwrap(),
                self.interrupt_status.clone(),
                intc.clone(),
                irq_line,
            );
            timesync.run();
        }

        let (sender, receiver) = unbounded();

        let thread = MuxerThread::new(
            self.cid,
            self.epoll.clone(),
            self.rxq.clone(),
            self.proxy_map.clone(),
            mem,
            queue,
            self.interrupt_evt.try_clone().unwrap(),
            self.interrupt_status.clone(),
            intc,
            irq_line,
            sender.clone(),
        );
        thread.run();

        self.reaper_sender = Some(sender);
        let reaper = ReaperThread::new(receiver, self.proxy_map.clone());
        reaper.run();
    }

    pub(crate) fn has_pending_rx(&self) -> bool {
        !self.rxq.lock().unwrap().is_empty()
    }

    pub(crate) fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> super::Result<()> {
        debug!("vsock: recv_stream_pkt");
        if self.rxq.lock().unwrap().is_empty() {
            return Err(VsockError::NoData);
        }

        if let Some(rx) = self.rxq.lock().unwrap().pop() {
            rx_to_pkt(self.cid, rx, pkt);
        }

        Ok(())
    }

    pub fn update_polling(&self, id: u64, fd: RawFd, evset: EventSet) {
        debug!("update_polling id={} fd={:?} evset={:?}", id, fd, evset);
        let _ = self
            .epoll
            .ctl(ControlOperation::Delete, fd, &EpollEvent::default());
        if !evset.is_empty() {
            let _ = self
                .epoll
                .ctl(ControlOperation::Add, fd, &EpollEvent::new(evset, id));
        }
    }

    fn process_proxy_update(&self, id: u64, update: ProxyUpdate) {
        if let Some(polling) = update.polling {
            self.update_polling(polling.0, polling.1, polling.2);
        }

        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                warn!("immediately removing proxy: {}", id);
                self.proxy_map.write().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                warn!("deferring proxy removal: {}", id);
                if let Some(reaper_sender) = &self.reaper_sender {
                    if reaper_sender.send(id).is_err() {
                        self.proxy_map.write().unwrap().remove(&id);
                    }
                }
            }
        }

        if update.signal_queue {
            self.interrupt_status
                .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
            if let Some(intc) = &self.intc {
                intc.lock().unwrap().set_irq(self.irq_line.unwrap());
            } else if let Err(e) = self.interrupt_evt.write(1) {
                warn!("failed to signal used queue: {:?}", e);
            }
        }
    }

    fn process_proxy_create(&self, pkt: &VsockPacket) {
        debug!("vsock: proxy create request");
        if let Some(req) = pkt.read_proxy_create() {
            debug!(
                "vsock: proxy create request: peer_port={}, type={}",
                req.peer_port, req._type
            );
            let mem = match self.mem.as_ref() {
                Some(m) => m,
                None => {
                    error!("proxy creation without mem");
                    return;
                }
            };
            let queue = match self.queue.as_ref() {
                Some(q) => q,
                None => {
                    error!("stream proxy creation without stream queue");
                    return;
                }
            };
            match req._type {
                defs::SOCK_STREAM => {
                    debug!("vsock: proxy create stream");
                    let id = (req.peer_port as u64) << 32 | defs::TSI_PROXY_PORT as u64;
                    match TcpProxy::new(
                        id,
                        self.cid,
                        defs::TSI_PROXY_PORT,
                        req.peer_port,
                        pkt.src_port(),
                        mem.clone(),
                        queue.clone(),
                        self.rxq.clone(),
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Mutex::new(Box::new(proxy)));
                        }
                        Err(e) => debug!("error creating tcp proxy: {}", e),
                    }
                }
                defs::SOCK_DGRAM => {
                    debug!("vsock: proxy create dgram");
                    let id = (req.peer_port as u64) << 32 | defs::TSI_PROXY_PORT as u64;
                    match UdpProxy::new(
                        id,
                        self.cid,
                        req.peer_port,
                        mem.clone(),
                        queue.clone(),
                        self.rxq.clone(),
                    ) {
                        Ok(proxy) => {
                            self.proxy_map
                                .write()
                                .unwrap()
                                .insert(id, Mutex::new(Box::new(proxy)));
                        }
                        Err(e) => debug!("error creating udp proxy: {}", e),
                    }
                }
                _ => debug!("vsock: unknown type on connection request"),
            };
        }
    }

    fn process_connect(&self, pkt: &VsockPacket) {
        debug!("vsock: proxy connect request");
        if let Some(req) = pkt.read_connect_req() {
            let id = (req.peer_port as u64) << 32 | defs::TSI_PROXY_PORT as u64;
            debug!("vsock: proxy connect request: id={}", id);
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map(|proxy| proxy.lock().unwrap().connect(pkt, req));

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_getname(&self, pkt: &VsockPacket) {
        debug!("vsock: new getname request");
        if let Some(req) = pkt.read_getname_req() {
            let id = (req.peer_port as u64) << 32 | (req.local_port as u64);
            debug!(
                "vsock: new getname request: id={}, peer_port={}, local_port={}",
                id, req.peer_port, req.local_port
            );

            if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                proxy.lock().unwrap().getpeername(pkt);
            }
        }
    }

    fn process_sendto_addr(&self, pkt: &VsockPacket) {
        debug!("vsock: new DGRAM sendto addr: src={}", pkt.src_port());
        if let Some(req) = pkt.read_sendto_addr() {
            let id = (req.peer_port as u64) << 32 | defs::TSI_PROXY_PORT as u64;
            debug!("vsock: new DGRAM sendto addr: id={}", id);
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map(|proxy| proxy.lock().unwrap().sendto_addr(req));

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_sendto_data(&self, pkt: &VsockPacket) {
        let id = (pkt.src_port() as u64) << 32 | defs::TSI_PROXY_PORT as u64;
        debug!("vsock: DGRAM sendto data: id={} src={}", id, pkt.src_port());
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().sendto_data(pkt);
        }
    }

    fn process_listen_request(&self, pkt: &VsockPacket) {
        debug!("vsock: DGRAM listen request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_listen_req() {
            let id = (req.peer_port as u64) << 32 | defs::TSI_PROXY_PORT as u64;
            debug!("vsock: DGRAM listen request: id={}", id);
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map(|proxy| proxy.lock().unwrap().listen(pkt, req, &self.host_port_map));

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_accept_request(&self, pkt: &VsockPacket) {
        debug!("vsock: DGRAM accept request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_accept_req() {
            let id = (req.peer_port as u64) << 32 | defs::TSI_PROXY_PORT as u64;
            debug!("vsock: DGRAM accept request: id={}", id);
            let update = self
                .proxy_map
                .read()
                .unwrap()
                .get(&id)
                .map(|proxy| proxy.lock().unwrap().accept(req));

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_proxy_release(&self, pkt: &VsockPacket) {
        debug!("vsock: DGRAM release request: src={}", pkt.src_port());
        if let Some(req) = pkt.read_release_req() {
            let id = (req.peer_port as u64) << 32 | req.local_port as u64;
            debug!(
                "vsock: DGRAM release request: id={} local_port={} peer_port={}",
                id, req.local_port, req.peer_port
            );
            let update = if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                Some(proxy.lock().unwrap().release())
            } else {
                debug!(
                    "release without proxy: id={}, proxies={}",
                    id,
                    self.proxy_map.read().unwrap().len()
                );
                None
            };

            if let Some(update) = update {
                self.process_proxy_update(id, update);
            }
        }
        debug!(
            "vsock: DGRAM release request: proxies={}",
            self.proxy_map.read().unwrap().len()
        );
    }

    fn process_dgram_rw(&self, pkt: &VsockPacket) {
        debug!("vsock: DGRAM OP_RW");
        let id = (pkt.src_port() as u64) << 32 | defs::TSI_PROXY_PORT as u64;

        if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!("vsock: DGRAM allowing OP_RW for {}", pkt.src_port());
            let mut proxy = proxy_lock.lock().unwrap();
            let update = proxy.sendmsg(pkt);
            self.process_proxy_update(id, update);
        } else {
            debug!("vsock: DGRAM ignoring OP_RW for {}", pkt.src_port());
        }
    }

    pub(crate) fn send_dgram_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        debug!(
            "vsock: send_dgram_pkt: src_port={} dst_port={}",
            pkt.src_port(),
            pkt.dst_port()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            debug!(
                "vsock: dropping guest packet for unknown CID: {:?}",
                pkt.hdr()
            );
            return Ok(());
        }

        match pkt.dst_port() {
            defs::TSI_PROXY_CREATE => self.process_proxy_create(pkt),
            defs::TSI_CONNECT => self.process_connect(pkt),
            defs::TSI_GETNAME => self.process_getname(pkt),
            defs::TSI_SENDTO_ADDR => self.process_sendto_addr(pkt),
            defs::TSI_SENDTO_DATA => self.process_sendto_data(pkt),
            defs::TSI_LISTEN => self.process_listen_request(pkt),
            defs::TSI_ACCEPT => self.process_accept_request(pkt),
            defs::TSI_PROXY_RELEASE => self.process_proxy_release(pkt),
            _ => {
                if pkt.op() == uapi::VSOCK_OP_RW {
                    self.process_dgram_rw(pkt);
                } else {
                    error!("unexpected dgram pkt: {}", pkt.op());
                }
            }
        }

        Ok(())
    }

    fn process_op_request(&mut self, pkt: &VsockPacket) {
        debug!("vsock: OP_REQUEST");
        let id: u64 = (pkt.src_port() as u64) << 32 | pkt.dst_port() as u64;
        let mut proxy_map = self.proxy_map.write().unwrap();

        if let Some(proxy) = proxy_map.get(&id) {
            proxy.lock().unwrap().confirm_connect(pkt)
        } else if let Some(ref mut ipc_map) = &mut self.unix_ipc_port_map {
            if let Some(path) = ipc_map.get(&pkt.dst_port()) {
                let mem = self.mem.as_ref().unwrap();
                let queue = self.queue.as_ref().unwrap();
                let rxq = self.rxq.clone();

                let mut unix = UnixProxy::new(
                    id,
                    self.cid,
                    pkt.dst_port(),
                    pkt.src_port(),
                    mem.clone(),
                    queue.clone(),
                    rxq,
                    path.to_path_buf(),
                )
                .unwrap();
                let tsi = TsiConnectReq {
                    peer_port: 0,
                    addr: Ipv4Addr::new(0, 0, 0, 0),
                    port: 0,
                };
                let update = unix.connect(pkt, tsi);
                unix.confirm_connect(pkt);
                proxy_map.insert(id, Mutex::new(Box::new(unix)));
                self.process_proxy_update(id, update);
            }
        }
    }

    fn process_op_response(&self, pkt: &VsockPacket) {
        debug!("vsock: OP_RESPONSE");
        let id: u64 = (pkt.src_port() as u64) << 32 | pkt.dst_port() as u64;
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().process_op_response(pkt));
        update
            .as_ref()
            .and_then(|u| u.push_accept)
            .and_then(|(_id, parent_id)| {
                self.proxy_map
                    .read()
                    .unwrap()
                    .get(&parent_id)
                    .map(|proxy| proxy.lock().unwrap().enqueue_accept())
            });

        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_op_shutdown(&self, pkt: &VsockPacket) {
        debug!("vsock: OP_SHUTDOWN");
        let id: u64 = (pkt.src_port() as u64) << 32 | pkt.dst_port() as u64;
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().shutdown(pkt);
        }
    }

    fn process_op_credit_update(&self, pkt: &VsockPacket) {
        debug!("vsock: OP_CREDIT_UPDATE");
        let id: u64 = (pkt.src_port() as u64) << 32 | pkt.dst_port() as u64;
        let update = self
            .proxy_map
            .read()
            .unwrap()
            .get(&id)
            .map(|proxy| proxy.lock().unwrap().update_peer_credit(pkt));
        if let Some(update) = update {
            self.process_proxy_update(id, update);
        }
    }

    fn process_stream_rw(&self, pkt: &VsockPacket) {
        debug!("vsock: OP_RW");
        let id: u64 = (pkt.src_port() as u64) << 32 | pkt.dst_port() as u64;
        if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!(
                "vsock: allowing OP_RW: src={} dst={}",
                pkt.src_port(),
                pkt.dst_port()
            );
            let mut proxy = proxy_lock.lock().unwrap();
            let update = proxy.sendmsg(pkt);
            self.process_proxy_update(id, update);
        } else {
            debug!("vsock: invalid OP_RW for {}, sending reset", pkt.src_port());
            let mem = match self.mem.as_ref() {
                Some(m) => m,
                None => {
                    warn!("OP_RW without mem");
                    return;
                }
            };
            let queue = match self.queue.as_ref() {
                Some(q) => q,
                None => {
                    warn!("OP_RW without queue");
                    return;
                }
            };

            // This response goes to the connection.
            let rx = MuxerRx::Reset {
                local_port: pkt.dst_port(),
                peer_port: pkt.src_port(),
            };
            push_packet(self.cid, rx, &self.rxq, queue, mem);
        }
    }

    fn process_stream_rst(&self, pkt: &VsockPacket) {
        debug!("vsock: OP_RST");
        let id: u64 = (pkt.src_port() as u64) << 32 | pkt.dst_port() as u64;
        if let Some(proxy_lock) = self.proxy_map.read().unwrap().get(&id) {
            debug!(
                "vsock: allowing OP_RST: id={} src={} dst={}",
                id,
                pkt.src_port(),
                pkt.dst_port()
            );
            let mut proxy = proxy_lock.lock().unwrap();
            let update = proxy.release();
            self.process_proxy_update(id, update);
        } else {
            debug!("vsock: invalid OP_RST for {}", pkt.src_port());
        }
    }

    pub(crate) fn send_stream_pkt(&mut self, pkt: &VsockPacket) -> super::Result<()> {
        debug!(
            "vsock: send_pkt: src_port={} dst_port={}, op={}",
            pkt.src_port(),
            pkt.dst_port(),
            pkt.op()
        );

        if pkt.dst_cid() != uapi::VSOCK_HOST_CID {
            debug!(
                "vsock: dropping guest packet for unknown CID: {:?}",
                pkt.hdr()
            );
            return Ok(());
        }

        match pkt.op() {
            uapi::VSOCK_OP_REQUEST => self.process_op_request(pkt),
            uapi::VSOCK_OP_RESPONSE => self.process_op_response(pkt),
            uapi::VSOCK_OP_SHUTDOWN => self.process_op_shutdown(pkt),
            uapi::VSOCK_OP_CREDIT_UPDATE => self.process_op_credit_update(pkt),
            uapi::VSOCK_OP_RW => self.process_stream_rw(pkt),
            uapi::VSOCK_OP_RST => self.process_stream_rst(pkt),
            _ => warn!("stream: unhandled op={}", pkt.op()),
        }
        Ok(())
    }
}

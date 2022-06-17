use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use super::super::super::legacy::Gic;
use super::super::Queue as VirtQueue;
use super::super::VIRTIO_MMIO_INT_VRING;
use super::defs;
use super::defs::uapi;
use super::muxer_rxq::{rx_to_pkt, MuxerRxQ};
use super::muxer_thread::MuxerThread;
use super::packet::{TsiGetnameRsp, VsockPacket};
use super::proxy::{Proxy, ProxyUpdate};
use super::tcp::TcpProxy;
use super::udp::UdpProxy;
use super::VsockError;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

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
            queue.add_used(mem, head.index, pkt.hdr().len() as u32 + pkt.len());
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
    queue_stream: Option<Arc<Mutex<VirtQueue>>>,
    queue_dgram: Option<Arc<Mutex<VirtQueue>>>,
    mem: Option<GuestMemoryMmap>,
    rxq_stream: Arc<Mutex<MuxerRxQ>>,
    rxq_dgram: Arc<Mutex<MuxerRxQ>>,
    epoll: Epoll,
    interrupt_evt: EventFd,
    interrupt_status: Arc<AtomicUsize>,
    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
    proxy_map: ProxyMap,
}

impl VsockMuxer {
    pub(crate) fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        interrupt_evt: EventFd,
        interrupt_status: Arc<AtomicUsize>,
    ) -> Self {
        VsockMuxer {
            cid,
            host_port_map,
            queue_stream: None,
            queue_dgram: None,
            mem: None,
            rxq_stream: Arc::new(Mutex::new(MuxerRxQ::new())),
            rxq_dgram: Arc::new(Mutex::new(MuxerRxQ::new())),
            epoll: Epoll::new().unwrap(),
            interrupt_evt,
            interrupt_status,
            intc: None,
            irq_line: None,
            proxy_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub(crate) fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        queue_stream: Arc<Mutex<VirtQueue>>,
        queue_dgram: Arc<Mutex<VirtQueue>>,
        intc: Option<Arc<Mutex<Gic>>>,
        irq_line: Option<u32>,
    ) {
        self.queue_stream = Some(queue_stream.clone());
        self.queue_dgram = Some(queue_dgram.clone());
        self.mem = Some(mem.clone());
        self.intc = intc.clone();
        self.irq_line = irq_line;

        let thread = MuxerThread::new(
            self.cid,
            self.epoll.clone(),
            self.rxq_stream.clone(),
            self.rxq_dgram.clone(),
            self.proxy_map.clone(),
            mem,
            queue_stream,
            queue_dgram,
            self.interrupt_evt.try_clone().unwrap(),
            self.interrupt_status.clone(),
            intc,
            irq_line,
        );
        thread.run();
    }

    pub(crate) fn has_pending_stream_rx(&self) -> bool {
        !self.rxq_stream.lock().unwrap().is_empty()
    }

    pub(crate) fn has_pending_dgram_rx(&self) -> bool {
        !self.rxq_dgram.lock().unwrap().is_empty()
    }

    pub(crate) fn recv_stream_pkt(&mut self, pkt: &mut VsockPacket) -> super::Result<()> {
        debug!("vsock: recv_stream_pkt");
        if self.rxq_stream.lock().unwrap().is_empty() {
            return Err(VsockError::NoData);
        }

        if let Some(rx) = self.rxq_stream.lock().unwrap().pop() {
            rx_to_pkt(self.cid, rx, pkt);
        }

        Ok(())
    }

    pub(crate) fn recv_dgram_pkt(&mut self, pkt: &mut VsockPacket) -> super::Result<()> {
        debug!("vsock: recv_dgram_pkt");
        if self.rxq_dgram.lock().unwrap().is_empty() {
            return Err(VsockError::NoData);
        }

        if let Some(rx) = self.rxq_dgram.lock().unwrap().pop() {
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
            let _ = self.epoll.ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(evset, id as u64),
            );
        }
    }

    fn process_proxy_update(&self, id: u64, update: ProxyUpdate) {
        if let Some(polling) = update.polling {
            self.update_polling(polling.0, polling.1, polling.2);
        }

        if update.remove_proxy {
            self.proxy_map.write().unwrap().remove(&id);
        }

        if update.signal_queue {
            self.interrupt_status
                .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
            if let Err(e) = self.interrupt_evt.write(1) {
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
            let queue_stream = match self.queue_stream.as_ref() {
                Some(q) => q,
                None => {
                    error!("stream proxy creation without stream queue");
                    return;
                }
            };
            let queue_dgram = match self.queue_dgram.as_ref() {
                Some(q) => q,
                None => {
                    error!("dgram proxy creation without dgram queue");
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
                        queue_stream.clone(),
                        queue_dgram.clone(),
                        self.rxq_stream.clone(),
                        self.rxq_dgram.clone(),
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
                        queue_dgram.clone(),
                        self.rxq_dgram.clone(),
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

    fn process_op_request(&self, pkt: &VsockPacket) {
        debug!("vsock: OP_REQUEST");
        let id: u64 = (pkt.src_port() as u64) << 32 | pkt.dst_port() as u64;
        if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
            proxy.lock().unwrap().confirm_connect(pkt)
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
            let queue = match self.queue_stream.as_ref() {
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
            push_packet(self.cid, rx, &self.rxq_stream, queue, mem);
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
            _ => warn!("stream: unhandled op={}", pkt.op()),
        }
        Ok(())
    }
}

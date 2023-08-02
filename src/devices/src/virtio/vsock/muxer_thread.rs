use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use super::super::super::legacy::Gic;
use super::super::Queue as VirtQueue;
use super::super::VIRTIO_MMIO_INT_VRING;
use super::muxer::{push_packet, MuxerRx, ProxyMap};
use super::muxer_rxq::MuxerRxQ;
use super::proxy::{ProxyRemoval, ProxyUpdate};
use super::tcp::TcpProxy;

use crossbeam_channel::Sender;
use rand::{rngs::ThreadRng, thread_rng, Rng};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

pub struct MuxerThread {
    cid: u64,
    pub epoll: Epoll,
    rxq: Arc<Mutex<MuxerRxQ>>,
    proxy_map: ProxyMap,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    interrupt_evt: EventFd,
    interrupt_status: Arc<AtomicUsize>,
    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
    reaper_sender: Sender<u64>,
}

impl MuxerThread {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cid: u64,
        epoll: Epoll,
        rxq: Arc<Mutex<MuxerRxQ>>,
        proxy_map: ProxyMap,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt_evt: EventFd,
        interrupt_status: Arc<AtomicUsize>,
        intc: Option<Arc<Mutex<Gic>>>,
        irq_line: Option<u32>,
        reaper_sender: Sender<u64>,
    ) -> Self {
        MuxerThread {
            cid,
            epoll,
            rxq,
            proxy_map,
            mem,
            queue,
            interrupt_evt,
            interrupt_status,
            intc,
            irq_line,
            reaper_sender,
        }
    }

    pub fn run(self) {
        thread::spawn(|| self.work());
    }

    fn send_credit_request(&self, credit_rx: MuxerRx) {
        debug!("send_credit_request");
        push_packet(self.cid, credit_rx, &self.rxq, &self.queue, &self.mem);
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

    fn process_proxy_update(&self, id: u64, update: ProxyUpdate, thread_rng: &mut ThreadRng) {
        if let Some(polling) = update.polling {
            self.update_polling(polling.0, polling.1, polling.2);
        }

        if let Some(credit_rx) = update.push_credit_req {
            debug!("send_credit_request");
            self.send_credit_request(credit_rx);
        }

        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                warn!("immediately removing proxy: {}", id);
                self.proxy_map.write().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                warn!("deferring proxy removal: {}", id);
                if self.reaper_sender.send(id).is_err() {
                    self.proxy_map.write().unwrap().remove(&id);
                }
            }
        }

        let mut should_signal = update.signal_queue;

        if let Some((peer_port, accept_fd)) = update.new_proxy {
            let local_port: u32 = thread_rng.gen_range(1024..u32::MAX);
            let new_id: u64 = (peer_port as u64) << 32 | local_port as u64;
            let new_proxy = TcpProxy::new_reverse(
                new_id,
                self.cid,
                id,
                local_port,
                peer_port,
                accept_fd,
                self.mem.clone(),
                self.queue.clone(),
                self.rxq.clone(),
            );
            self.proxy_map
                .write()
                .unwrap()
                .insert(new_id, Mutex::new(Box::new(new_proxy)));
            if let Some(proxy) = self.proxy_map.read().unwrap().get(&new_id) {
                proxy.lock().unwrap().push_op_request();
            };
            should_signal = true;
        }

        if should_signal {
            debug!("signal IRQ");
            self.interrupt_status
                .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
            if let Some(intc) = &self.intc {
                intc.lock().unwrap().set_irq(self.irq_line.unwrap());
            } else if let Err(e) = self.interrupt_evt.write(1) {
                warn!("failed to signal used queue: {:?}", e);
            }
        }
    }

    fn work(self) {
        let mut thread_rng = thread_rng();
        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match self
                .epoll
                .wait(epoll_events.len(), -1, epoll_events.as_mut_slice())
            {
                Ok(ev_cnt) => {
                    for ev in &epoll_events[0..ev_cnt] {
                        debug!("Event: ev.data={} ev.fd={}", ev.data(), ev.fd());
                        let evset = EventSet::from_bits(ev.events).unwrap();
                        let id = ev.data();

                        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy_lock| {
                            let mut proxy = proxy_lock.lock().unwrap();
                            proxy.process_event(evset)
                        });

                        if let Some(update) = update {
                            self.process_proxy_update(id, update, &mut thread_rng);
                        }
                    }
                }
                Err(e) => {
                    debug!("vsock: failed to consume muxer epoll event: {}", e);
                }
            }
        }
    }
}

use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::process;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::{get_win_size, Console, RXQ_INDEX, TXQ_INDEX};
use crate::virtio::device::VirtioDevice;

impl Console {
    pub(crate) fn handle_rxq_event(&mut self, event: &EpollEvent) -> bool {
        debug!("console: RX queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("console: rxq unexpected event {:?}", event_set);
            return false;
        }

        let mut raise_irq = false;
        if let Err(e) = self.queue_events[RXQ_INDEX].read() {
            error!("Failed to get console rx queue event: {:?}", e);
        } else {
            raise_irq |= self.process_rx();
        }
        raise_irq
    }

    pub(crate) fn handle_txq_event(&mut self, event: &EpollEvent) -> bool {
        debug!("console: TX queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("console: txq unexpected event {:?}", event_set);
            return false;
        }

        let mut raise_irq = false;
        if let Err(e) = self.queue_events[TXQ_INDEX].read() {
            error!("Failed to get console tx queue event: {:?}", e);
        } else {
            raise_irq |= self.process_tx();
        }
        raise_irq
    }

    pub(crate) fn handle_input(&mut self, event: &EpollEvent) {
        debug!("console: input event");

        let event_set = event.event_set();
        match event_set {
            EventSet::HANG_UP => process::exit(0),
            EventSet::IN => {}
            _ => {
                warn!("console: input unexpected event {:?}", event_set);
                return;
            }
        }

        let mut out = [0u8; 64];
        let count = self.input.read(&mut out).unwrap();
        self.in_buffer.extend(&out[..count]);

        if self.process_rx() {
            self.signal_used_queue().unwrap();
        }
    }

    fn handle_activate_event(&self, event_manager: &mut EventManager) {
        debug!("console: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume console activate event: {:?}", e);
        }

        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = event_manager
            .subscriber(self.activate_evt.as_raw_fd())
            .unwrap();

        event_manager
            .register(
                self.queue_events[RXQ_INDEX].as_raw_fd(),
                EpollEvent::new(
                    EventSet::IN,
                    self.queue_events[RXQ_INDEX].as_raw_fd() as u64,
                ),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register fs rxq with event manager: {:?}", e);
            });

        event_manager
            .register(
                self.queue_events[TXQ_INDEX].as_raw_fd(),
                EpollEvent::new(
                    EventSet::IN,
                    self.queue_events[TXQ_INDEX].as_raw_fd() as u64,
                ),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register fs txq with event manager: {:?}", e);
            });

        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!("Failed to unregister fs activate evt: {:?}", e);
            })
    }

    fn handle_sigwinch_event(&mut self, event: &EpollEvent) {
        debug!("console: SIGWINCH event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("console: sigwinch unexpected event {:?}", event_set);
        }

        if let Err(e) = self.sigwinch_evt.read() {
            error!("Failed to read the sigwinch event: {:?}", e);
        }

        let (cols, rows) = get_win_size();
        self.update_console_size(cols, rows);
    }
}

impl Subscriber for Console {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let rxq = self.queue_events[RXQ_INDEX].as_raw_fd();
        let txq = self.queue_events[TXQ_INDEX].as_raw_fd();
        let activate_evt = self.activate_evt.as_raw_fd();
        let sigwinch_evt = self.sigwinch_evt.as_raw_fd();
        let input = self.input.as_raw_fd();

        if self.is_activated() {
            let mut raise_irq = false;
            match source {
                _ if source == rxq => raise_irq = self.handle_rxq_event(event),
                _ if source == txq => raise_irq = self.handle_txq_event(event),
                _ if source == input => self.handle_input(event),
                _ if source == activate_evt => {
                    self.handle_activate_event(event_manager);
                }
                _ if source == sigwinch_evt => {
                    self.handle_sigwinch_event(event);
                }
                _ => warn!("Unexpected console event received: {:?}", source),
            }
            if raise_irq {
                self.signal_used_queue().unwrap_or_default();
            }
        } else {
            warn!(
                "console: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        if self.interactive {
            vec![
                EpollEvent::new(EventSet::IN, self.activate_evt.as_raw_fd() as u64),
                EpollEvent::new(EventSet::IN, self.sigwinch_evt.as_raw_fd() as u64),
                EpollEvent::new(EventSet::IN, self.input.as_raw_fd() as u64),
            ]
        } else {
            vec![
                EpollEvent::new(EventSet::IN, self.activate_evt.as_raw_fd() as u64),
                EpollEvent::new(EventSet::IN, self.sigwinch_evt.as_raw_fd() as u64),
            ]
        }
    }
}

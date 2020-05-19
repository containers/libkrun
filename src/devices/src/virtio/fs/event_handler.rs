use std::os::unix::io::AsRawFd;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::{Fs, HPQ_INDEX, REQ_INDEX};
use crate::virtio::device::VirtioDevice;

impl Fs {
    fn handle_activate_event(&self, event_manager: &mut EventManager) {
        debug!("Fs: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume fs activate event: {:?}", e);
        }

        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = event_manager
            .subscriber(self.activate_evt.as_raw_fd())
            .unwrap();

        event_manager
            .register(
                self.queue_events[HPQ_INDEX].as_raw_fd(),
                EpollEvent::new(
                    EventSet::IN,
                    self.queue_events[HPQ_INDEX].as_raw_fd() as u64,
                ),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register fs hpq with event manager: {:?}", e);
            });

        event_manager
            .register(
                self.queue_events[REQ_INDEX].as_raw_fd(),
                EpollEvent::new(
                    EventSet::IN,
                    self.queue_events[REQ_INDEX].as_raw_fd() as u64,
                ),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register fs req with event manager: {:?}", e);
            });

        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!("Failed to unregister fs activate evt: {:?}", e);
            })
    }
}

impl Subscriber for Fs {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let hpq = self.queue_events[HPQ_INDEX].as_raw_fd();
        let req = self.queue_events[REQ_INDEX].as_raw_fd();
        let activate_evt = self.activate_evt.as_raw_fd();

        if self.is_activated() {
            match source {
                _ if source == hpq => self.handle_hpq_event(),
                _ if source == req => self.handle_req_event(),
                _ if source == activate_evt => {
                    self.handle_activate_event(event_manager);
                }
                _ => warn!("Unexpected fs event received: {:?}", source),
            }
        } else {
            warn!(
                "Fs: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.activate_evt.as_raw_fd() as u64,
        )]
    }
}

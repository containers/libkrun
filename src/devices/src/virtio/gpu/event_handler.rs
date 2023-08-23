use std::os::unix::io::AsRawFd;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::{Gpu, CTL_INDEX, CUR_INDEX};
use crate::virtio::device::VirtioDevice;

impl Gpu {
    pub(crate) fn handle_ctl_event(&mut self, event: &EpollEvent) {
        debug!("gpu: request queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("gpu: request queue unexpected event {:?}", event_set);
            return;
        }

        if let Err(e) = self.queue_events[CTL_INDEX].read() {
            error!("Failed to read request queue event: {:?}", e);
        } else if let Err(e) = self.sender.as_ref().unwrap().send(CTL_INDEX as u64) {
            error!("Failed to signal worker for queue {CTL_INDEX}: {:?}", e);
        }
    }

    pub(crate) fn handle_cur_event(&mut self, event: &EpollEvent) {
        debug!("gpu: request queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("gpu: request queue unexpected event {:?}", event_set);
            return;
        }

        if let Err(e) = self.queue_events[CUR_INDEX].read() {
            error!("Failed to read request queue event: {:?}", e);
        } else if let Err(e) = self.sender.as_ref().unwrap().send(CUR_INDEX as u64) {
            error!("Failed to signal worker for queue {CUR_INDEX}: {:?}", e);
        }
    }

    fn handle_activate_event(&self, event_manager: &mut EventManager) {
        debug!("gpu: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume gpu activate event: {:?}", e);
        }

        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = event_manager
            .subscriber(self.activate_evt.as_raw_fd())
            .unwrap();

        event_manager
            .register(
                self.queue_events[CTL_INDEX].as_raw_fd(),
                EpollEvent::new(
                    EventSet::IN,
                    self.queue_events[CTL_INDEX].as_raw_fd() as u64,
                ),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register gpu ctl with event manager: {:?}", e);
            });

        event_manager
            .register(
                self.queue_events[CUR_INDEX].as_raw_fd(),
                EpollEvent::new(
                    EventSet::IN,
                    self.queue_events[CUR_INDEX].as_raw_fd() as u64,
                ),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!("Failed to register gpu cur with event manager: {:?}", e);
            });

        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!("Failed to unregister gpu activate evt: {:?}", e);
            })
    }
}

impl Subscriber for Gpu {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let ctl = self.queue_events[CTL_INDEX].as_raw_fd();
        let cur = self.queue_events[CUR_INDEX].as_raw_fd();
        let activate_evt = self.activate_evt.as_raw_fd();

        if self.is_activated() {
            match source {
                _ if source == ctl => self.handle_ctl_event(event),
                _ if source == cur => self.handle_cur_event(event),
                _ if source == activate_evt => {
                    self.handle_activate_event(event_manager);
                }
                _ => warn!("Unexpected gpu event received: {:?}", source),
            }
        } else {
            warn!(
                "gpu: The device is not yet activated. Spurious event received: {:?}",
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

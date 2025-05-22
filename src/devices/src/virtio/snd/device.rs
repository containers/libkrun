use std::io::Write;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::thread::JoinHandle;

use utils::eventfd::EventFd;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{ActivateError, ActivateResult, Queue as VirtQueue, VirtioDevice};
use super::virtio_sound::VirtioSoundConfig;
use super::worker::SndWorker;
use super::{defs, defs::uapi, defs::QUEUE_INDEXES, Error};

use crate::legacy::IrqChip;
use crate::virtio::DeviceState;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioSnd {}

pub struct Snd {
    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) interrupt_evt: EventFd,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    intc: Option<IrqChip>,
    irq_line: Option<u32>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
}

impl Snd {
    pub(crate) fn with_queues(queues: Vec<VirtQueue>) -> super::Result<Snd> {
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events
                .push(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFdCreate)?);
        }

        Ok(Snd {
            queues,
            queue_events,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(Error::EventFdCreate)?,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(Error::EventFdCreate)?,
            device_state: DeviceState::Inactive,
            intc: None,
            irq_line: None,
            worker_thread: None,
            worker_stopfd: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(Error::EventFdCreate)?,
        })
    }

    pub fn new() -> super::Result<Snd> {
        let queues: Vec<VirtQueue> = defs::QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(queues)
    }

    pub fn id(&self) -> &str {
        defs::SND_DEV_ID
    }

    pub fn set_intc(&mut self, intc: IrqChip) {
        self.intc = Some(intc);
    }
}

impl VirtioDevice for Snd {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_SND
    }

    fn queues(&self) -> &[VirtQueue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [VirtQueue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn set_irq_line(&mut self, irq: u32) {
        debug!("SET_IRQ_LINE (SND)={irq}");
        self.irq_line = Some(irq);
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config = VirtioSoundConfig {
            jacks: 0.into(),
            streams: 2.into(),
            chmaps: 1.into(),
        };

        let config_slice = config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..std::cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "snd: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.worker_thread.is_some() {
            panic!("virtio_snd: worker thread already exists");
        }

        if self.queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                self.queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        let event_idx: bool = (self.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        for idx in QUEUE_INDEXES {
            self.queues[idx].set_event_idx(event_idx);
        }

        let queue_evts = self
            .queue_events
            .iter()
            .map(|e| e.try_clone().unwrap())
            .collect();
        let worker = SndWorker::new(
            self.queues.clone(),
            queue_evts,
            self.interrupt_status.clone(),
            self.interrupt_evt.try_clone().unwrap(),
            self.intc.clone(),
            self.irq_line,
            mem.clone(),
            self.worker_stopfd.try_clone().unwrap(),
        );
        self.worker_thread = Some(worker.run());

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        self.device_state = DeviceState::Inactive;
        true
    }
}

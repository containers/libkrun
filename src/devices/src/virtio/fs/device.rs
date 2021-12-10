use std::cmp;
use std::io::Write;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use utils::eventfd::EventFd;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceState, FsError, Queue as VirtQueue, VirtioDevice,
    VirtioShmRegion, VIRTIO_MMIO_INT_VRING,
};
use super::descriptor_utils::{Reader, Writer};
use super::passthrough::{self, PassthroughFs};
use super::server::Server;
use super::{defs, defs::uapi};
use crate::legacy::Gic;
use crate::Error as DeviceError;

// High priority queue.
pub(crate) const HPQ_INDEX: usize = 0;
// Request queue.
pub(crate) const REQ_INDEX: usize = 1;

pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; 36],
    num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; 36],
            num_request_queues: 0,
        }
    }
}

unsafe impl ByteValued for VirtioFsConfig {}

pub struct Fs {
    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) interrupt_evt: EventFd,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioFsConfig,
    shm_region: Option<VirtioShmRegion>,
    server: Server<PassthroughFs>,
    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
}

impl Fs {
    pub(crate) fn with_queues(
        fs_id: String,
        shared_dir: String,
        mapped_volumes: Option<Vec<(PathBuf, PathBuf)>>,
        queues: Vec<VirtQueue>,
    ) -> super::Result<Fs> {
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events
                .push(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(FsError::EventFd)?);
        }

        let tag = fs_id.into_bytes();
        let mut config = VirtioFsConfig::default();
        config.tag[..tag.len()].copy_from_slice(tag.as_slice());
        config.num_request_queues = 1;

        let fs_cfg = passthrough::Config {
            root_dir: shared_dir,
            mapped_volumes,
            ..Default::default()
        };

        Ok(Fs {
            queues,
            queue_events,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(FsError::EventFd)?,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(FsError::EventFd)?,
            device_state: DeviceState::Inactive,
            config,
            shm_region: None,
            server: Server::new(PassthroughFs::new(fs_cfg).unwrap()),
            intc: None,
            irq_line: None,
        })
    }

    pub fn new(
        fs_id: String,
        shared_dir: String,
        mapped_volumes: Option<Vec<(PathBuf, PathBuf)>>,
    ) -> super::Result<Fs> {
        let queues: Vec<VirtQueue> = defs::QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(fs_id, shared_dir, mapped_volumes, queues)
    }

    pub fn id(&self) -> &str {
        defs::FS_DEV_ID
    }

    pub fn set_intc(&mut self, intc: Arc<Mutex<Gic>>) {
        self.intc = Some(intc);
    }

    pub fn set_shm_region(&mut self, shm_region: VirtioShmRegion) {
        self.shm_region = Some(shm_region);
    }

    /// Signal the guest driver that we've used some virtio buffers that it had previously made
    /// available.
    pub fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        debug!("fs: raising IRQ");
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        if let Some(intc) = &self.intc {
            intc.lock().unwrap().set_irq(self.irq_line.unwrap());
            Ok(())
        } else {
            self.interrupt_evt.write(1).map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
        }
    }

    pub(crate) fn handle_hpq_event(&mut self) {
        debug!("Fs: HPQ queue event");
        if let Err(e) = self.queue_events[0].read() {
            error!("Failed to get queue event: {:?}", e);
        } else if self.process_queue(0) {
            let _ = self.signal_used_queue();
        }
    }

    pub(crate) fn handle_req_event(&mut self) {
        debug!("Fs: REQ queue event");
        if let Err(e) = self.queue_events[1].read() {
            error!("Failed to get queue event: {:?}", e);
        } else if self.process_queue(1) {
            let _ = self.signal_used_queue();
        }
    }

    pub(crate) fn process_queue(&mut self, queue_index: usize) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let queue = &mut self.queues[queue_index];
        let mut used_any = false;
        while let Some(head) = queue.pop(mem) {
            let reader = Reader::new(mem, head.clone())
                .map_err(FsError::QueueReader)
                .unwrap();
            let writer = Writer::new(mem, head.clone())
                .map_err(FsError::QueueWriter)
                .unwrap();

            self.server
                .handle_message(reader, writer, self.shm_region.as_ref())
                //.map_err(FsError::ProcessQueue)
                .unwrap();

            queue.add_used(mem, head.index, 0);
            used_any = true;
        }

        used_any
    }
}

impl VirtioDevice for Fs {
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
        uapi::VIRTIO_ID_FS
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
        self.irq_line = Some(irq);
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "fs: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                self.queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        self.shm_region.as_ref()
    }
}

#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use std::cmp;
use std::io::Write;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use utils::eventfd::{EventFd, EFD_NONBLOCK};
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;
use virtio_bindings::{virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX};
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{
    ActivateResult, DeviceState, FsError, Queue as VirtQueue, VirtioDevice, VirtioShmRegion,
};
use super::passthrough;
use super::worker::FsWorker;
use super::ExportTable;
use super::{defs, defs::uapi};
use crate::legacy::IrqChip;

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
    queues: Vec<VirtQueue>,
    queue_events: Vec<EventFd>,
    avail_features: u64,
    acked_features: u64,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    intc: Option<IrqChip>,
    irq_line: Option<u32>,
    device_state: DeviceState,
    config: VirtioFsConfig,
    shm_region: Option<VirtioShmRegion>,
    passthrough_cfg: passthrough::Config,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
}

impl Fs {
    pub(crate) fn with_queues(
        fs_id: String,
        shared_dir: String,
        exit_code: Arc<AtomicI32>,
        queues: Vec<VirtQueue>,
    ) -> super::Result<Fs> {
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events
                .push(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(FsError::EventFd)?);
        }

        let avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        let tag = fs_id.into_bytes();
        let mut config = VirtioFsConfig::default();
        config.tag[..tag.len()].copy_from_slice(tag.as_slice());
        config.num_request_queues = 1;

        let fs_cfg = passthrough::Config {
            root_dir: shared_dir,
            ..Default::default()
        };

        Ok(Fs {
            queues,
            queue_events,
            avail_features,
            acked_features: 0,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(FsError::EventFd)?,
            intc: None,
            irq_line: None,
            device_state: DeviceState::Inactive,
            config,
            shm_region: None,
            passthrough_cfg: fs_cfg,
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(FsError::EventFd)?,
            exit_code,
            #[cfg(target_os = "macos")]
            map_sender: None,
        })
    }

    pub fn new(fs_id: String, shared_dir: String, exit_code: Arc<AtomicI32>) -> super::Result<Fs> {
        let queues: Vec<VirtQueue> = defs::QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(fs_id, shared_dir, exit_code, queues)
    }

    pub fn id(&self) -> &str {
        defs::FS_DEV_ID
    }

    pub fn set_intc(&mut self, intc: IrqChip) {
        self.intc = Some(intc);
    }

    pub fn set_shm_region(&mut self, shm_region: VirtioShmRegion) {
        self.shm_region = Some(shm_region);
    }

    pub fn set_export_table(&mut self, export_table: ExportTable) -> u64 {
        static FS_UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

        self.passthrough_cfg.export_fsid = FS_UNIQUE_ID.fetch_add(1, Ordering::Relaxed);
        self.passthrough_cfg.export_table = Some(export_table);

        self.passthrough_cfg.export_fsid
    }

    #[cfg(target_os = "macos")]
    pub fn set_map_sender(&mut self, map_sender: Sender<WorkerMessage>) {
        self.map_sender = Some(map_sender);
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
        debug!("SET_IRQ_LINE (FS)={}", irq);
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
        if self.worker_thread.is_some() {
            panic!("virtio_fs: worker thread already exists");
        }

        let event_idx: bool = (self.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        self.queues[defs::HPQ_INDEX].set_event_idx(event_idx);
        self.queues[defs::REQ_INDEX].set_event_idx(event_idx);

        let queue_evts = self
            .queue_events
            .iter()
            .map(|e| e.try_clone().unwrap())
            .collect();
        let worker = FsWorker::new(
            self.queues.clone(),
            queue_evts,
            self.interrupt_status.clone(),
            self.interrupt_evt.try_clone().unwrap(),
            self.intc.clone(),
            self.irq_line,
            mem.clone(),
            self.shm_region.clone(),
            self.passthrough_cfg.clone(),
            self.worker_stopfd.try_clone().unwrap(),
            self.exit_code.clone(),
            #[cfg(target_os = "macos")]
            self.map_sender.clone(),
        );
        self.worker_thread = Some(worker.run());

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

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {:?}", e);
            }
        }
        self.device_state = DeviceState::Inactive;
        true
    }
}

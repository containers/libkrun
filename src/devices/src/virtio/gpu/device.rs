use std::io::Write;
use std::sync::{Arc, Mutex};

use crossbeam_channel::{unbounded, Sender};
use utils::eventfd::EventFd;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{
    fs::ExportTable, ActivateError, ActivateResult, DeviceQueue, DeviceState, GpuError,
    Queue as VirtQueue, QueueConfig, VirtioDevice, VirtioShmRegion,
};
use super::defs;
use super::defs::uapi;
use super::defs::uapi::virtio_gpu_config;
use super::worker::Worker;
use crate::virtio::display::DisplayInfo;
use crate::virtio::InterruptTransport;
use krun_display::DisplayBackend;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = (1u64 << uapi::VIRTIO_F_VERSION_1)
    | (1u64 << uapi::VIRTIO_GPU_F_VIRGL)
    | (1u64 << uapi::VIRTIO_GPU_F_EDID)
    | (1u64 << uapi::VIRTIO_GPU_F_RESOURCE_UUID)
    | (1u64 << uapi::VIRTIO_GPU_F_RESOURCE_BLOB)
    | (1u64 << uapi::VIRTIO_GPU_F_CONTEXT_INIT);

const QUEUE_SIZE: u16 = 256;
static QUEUE_CONFIG: [QueueConfig; defs::NUM_QUEUES] =
    [QueueConfig::new(QUEUE_SIZE); defs::NUM_QUEUES];

pub struct Gpu {
    pub(crate) queue_ctl: Option<Arc<Mutex<VirtQueue>>>,
    // Queue events stored for event handler - these are shared with DeviceQueue
    pub(crate) ctl_event: Option<Arc<EventFd>>,
    pub(crate) cur_event: Option<Arc<EventFd>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    shm_region: Option<VirtioShmRegion>,
    pub(crate) sender: Option<Sender<u64>>,
    virgl_flags: u32,
    #[cfg(target_os = "macos")]
    map_sender: Sender<WorkerMessage>,
    export_table: Option<ExportTable>,
    displays: Box<[DisplayInfo]>,
    display_backend: DisplayBackend<'static>,
}

impl Gpu {
    pub fn new(
        virgl_flags: u32,
        displays: Box<[DisplayInfo]>,
        display_backend: DisplayBackend<'static>,
        #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
    ) -> super::Result<Gpu> {
        Ok(Gpu {
            queue_ctl: None,
            ctl_event: None,
            cur_event: None,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(GpuError::EventFd)?,
            device_state: DeviceState::Inactive,
            shm_region: None,
            sender: None,
            virgl_flags,
            #[cfg(target_os = "macos")]
            map_sender,
            export_table: None,
            displays,
            display_backend,
        })
    }

    pub fn id(&self) -> &str {
        defs::GPU_DEV_ID
    }

    pub fn set_shm_region(&mut self, shm_region: VirtioShmRegion) {
        debug!("virtio_gpu: set_shm_region");
        self.shm_region = Some(shm_region);
    }

    pub fn set_export_table(&mut self, export_table: ExportTable) {
        self.export_table = Some(export_table);
    }

    /*
    pub fn process_ctl(&mut self) -> bool {
        debug!("gpu: process_ctl()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        //while let Some(head) = self.queues[CTL_INDEX].pop(mem) {
        if let Some(head) = self.queues[CTL_INDEX].pop(mem) {
            let index = head.index;
            let mut written = 0;
            for desc in head.into_iter() {
                error!("gpu: process_ctl() unimplemented");
                self.queues[CTL_INDEX].go_to_previous_position();
                break;
            }

            have_used = true;
            self.queues[CTL_INDEX].add_used(mem, index, written);
        }

        have_used
    }

    pub fn process_cur(&mut self) -> bool {
        debug!("gpu: process_cur()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        while let Some(head) = self.queues[CTL_INDEX].pop(mem) {
            let index = head.index;
            let mut written = 0;
            for desc in head.into_iter() {
                error!("gpu: process_cur() unimplemented");
                self.queues[CTL_INDEX].go_to_previous_position();
                break;
            }

            have_used = true;
            self.queues[CTL_INDEX].add_used(mem, index, written);
        }

        have_used
    }
    */
}

impl VirtioDevice for Gpu {
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
        uapi::VIRTIO_ID_GPU
    }

    fn device_name(&self) -> &str {
        "gpu"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config = virtio_gpu_config {
            events_read: 0,
            events_clear: 0,
            num_scanouts: self.displays.len() as u32,
            num_capsets: 5,
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
            "gpu: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        let [control_q, cursor_q]: [_; defs::NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!(
                "Cannot perform activate. Expected {} queue(s)",
                defs::NUM_QUEUES
            );
            ActivateError::BadActivate
        })?;

        let shm_region = match self.shm_region.as_ref() {
            Some(s) => s.clone(),
            None => panic!("virtio_gpu: missing SHM region"),
        };

        self.ctl_event = Some(control_q.event.clone());
        self.cur_event = Some(cursor_q.event.clone());
        let queue_ctl = Arc::new(Mutex::new(control_q.queue));
        self.queue_ctl = Some(queue_ctl.clone());
        // cursor queue not used by worker

        let (sender, receiver) = unbounded();
        let worker = Worker::new(
            receiver,
            mem.clone(),
            queue_ctl,
            interrupt.clone(),
            shm_region,
            self.virgl_flags,
            #[cfg(target_os = "macos")]
            self.map_sender.clone(),
            self.export_table.take(),
            self.displays.clone(),
            self.display_backend,
        );
        worker.run();

        self.sender = Some(sender);

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        debug!("virtio_gpu: GET_shm_region");
        self.shm_region.as_ref()
    }
}

use super::super::{
    ActivateError, ActivateResult, ConsoleError, DeviceState, Queue as VirtQueue, VirtioDevice,
};
use super::{defs, defs::control_event, defs::uapi};
use crate::virtio::console::console_control::{
    ConsoleControl, VirtioConsoleControl, VirtioConsoleResize,
};
use crate::virtio::console::defs::QUEUE_SIZE;
use crate::virtio::console::port::Port;
use crate::virtio::console::port_queue_mapping::{
    num_queues, port_id_to_queue_idx, QueueDirection,
};
use crate::virtio::{InterruptTransport, PortDescription, VmmExitObserver};
use std::cmp;
use std::io::Write;
use std::iter::zip;
use std::mem::{size_of, size_of_val};
use std::os::fd::BorrowedFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use utils::eventfd::EventFd;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap};

pub(crate) const CONTROL_RXQ_INDEX: usize = 2;
pub(crate) const CONTROL_TXQ_INDEX: usize = 3;

pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_CONSOLE_F_SIZE as u64)
    | (1 << uapi::VIRTIO_CONSOLE_F_MULTIPORT as u64)
    | (1 << uapi::VIRTIO_F_VERSION_1 as u64);

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleConfig {
    cols: u16,
    rows: u16,
    max_nr_ports: u32,
    emerg_wr: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioConsoleConfig {}

impl VirtioConsoleConfig {
    pub fn new(cols: u16, rows: u16, max_nr_ports: u32) -> Self {
        VirtioConsoleConfig {
            cols,
            rows,
            max_nr_ports,
            emerg_wr: 0u32,
        }
    }
}

pub struct Console {
    pub(crate) device_state: DeviceState,
    pub(crate) control: Arc<ConsoleControl>,
    pub(crate) ports: Vec<Port>,

    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) activate_evt: EventFd,
    pub(crate) sigwinch_evt: EventFd,

    config: VirtioConsoleConfig,
    ready: bool,
    console_ready_evt: Arc<EventFd>,
}

#[derive(Error, Debug)]
#[repr(i32)]
pub enum ConsoleControllerError {
    #[error("Console device is not ready to ")]
    NotReady,

    #[error("Backend implementation error")]
    OutOfPorts,
}

#[derive(Clone)]
pub struct ConsoleController {
    console: Arc<Mutex<Console>>,
}

impl ConsoleController {
    pub fn console_ready_fd(&self) -> BorrowedFd<'_> {
        unsafe {
            BorrowedFd::borrow_raw(self.console.lock().unwrap().console_ready_evt.as_raw_fd())
        }
    }

    pub fn is_ready(&self) -> bool {
        self.console.lock().unwrap().ready
    }

    pub fn add_port(
        &self,
        port_description: PortDescription,
    ) -> Result<(), ConsoleControllerError> {
        let mut console = self.console.lock().unwrap();
        if !console.ready {
            return Err(ConsoleControllerError::NotReady);
        }

        if console.ports.len() as u32 >= console.config.max_nr_ports {
            return Err(ConsoleControllerError::OutOfPorts);
        }

        let port_id = console.ports.len() as u32;
        console.ports.push(Port::new(port_id, port_description));

        // Notify the guest we have added a port
        // From this point forward, we will automatically set up the port as open and start worker
        // threads once we receive the VIRTIO_CONSOLE_PORT_READY
        console.control.port_add(port_id);
        Ok(())
    }
}

impl Console {
    pub fn new(
        ports: Vec<PortDescription>,
        reserved_port_count: u32,
        console_ready_evt: Arc<EventFd>,
    ) -> super::Result<Console> {
        assert!(
            !ports.is_empty() || reserved_port_count > 0,
            "Expected at least 1 port or reserved port"
        );

        let max_ports = ports.len() as u32 + reserved_port_count;

        // Pre-allocate queues for all potential ports
        let num_queues = num_queues(max_ports as usize);
        let queues = vec![VirtQueue::new(QUEUE_SIZE); num_queues];

        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events
                .push(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(ConsoleError::EventFd)?);
        }

        let ports: Vec<Port> = zip(0u32.., ports)
            .map(|(port_id, description)| Port::new(port_id, description))
            .collect();

        let (cols, rows) = ports
            .first()
            .and_then(|p| p.terminal())
            .map(|t| t.get_win_size())
            .unwrap_or((0, 0));

        let config = VirtioConsoleConfig::new(cols, rows, max_ports);

        Ok(Console {
            control: ConsoleControl::new(),
            ports,
            queues,
            queue_events,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(ConsoleError::EventFd)?,
            sigwinch_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(ConsoleError::EventFd)?,
            device_state: DeviceState::Inactive,
            config,
            ready: false,
            console_ready_evt,
        })
    }

    pub fn with_controller(
        ports: Vec<PortDescription>,
        reserved_port_count: u32,
        console_ready_evt: Arc<EventFd>,
    ) -> super::Result<(Arc<Mutex<Console>>, ConsoleController)> {
        let console = Arc::new(Mutex::new(Self::new(
            ports,
            reserved_port_count,
            console_ready_evt,
        )?));
        Ok((console.clone(), ConsoleController { console }))
    }

    pub fn id(&self) -> &str {
        defs::CONSOLE_DEV_ID
    }

    pub fn get_sigwinch_fd(&self) -> RawFd {
        self.sigwinch_evt.as_raw_fd()
    }

    pub fn update_console_size(&mut self, port_id: u32, cols: u16, rows: u16) {
        log::debug!("update_console_size {port_id}: {cols} {rows}");
        self.control
            .console_resize(port_id, VirtioConsoleResize { rows, cols });
    }

    pub(crate) fn process_control_rx(&mut self) -> bool {
        log::trace!("process_control_rx");
        let DeviceState::Activated(ref mem, _) = self.device_state else {
            unreachable!()
        };
        let mut raise_irq = false;

        while let Some(head) = self.queues[CONTROL_RXQ_INDEX].pop(mem) {
            if let Some(buf) = self.control.queue_pop() {
                match mem.write(&buf, head.addr) {
                    Ok(n) => {
                        if n != buf.len() {
                            log::error!("process_control_rx: partial write");
                        }
                        raise_irq = true;
                        log::trace!("process_control_rx wrote {n}");
                        if let Err(e) =
                            self.queues[CONTROL_RXQ_INDEX].add_used(mem, head.index, n as u32)
                        {
                            error!("failed to add used elements to the queue: {e:?}");
                        }
                    }
                    Err(e) => {
                        log::error!("process_control_rx failed to write: {e}");
                    }
                }
            } else {
                self.queues[CONTROL_RXQ_INDEX].undo_pop();
                break;
            }
        }
        raise_irq
    }

    pub(crate) fn process_control_tx(&mut self) -> bool {
        log::trace!("process_control_tx");
        let DeviceState::Activated(ref mem, ref interrupt) = self.device_state else {
            unreachable!()
        };

        let tx_queue = &mut self.queues[CONTROL_TXQ_INDEX];
        let mut raise_irq = false;

        let mut ports_to_start = Vec::new();

        while let Some(head) = tx_queue.pop(mem) {
            raise_irq = true;

            let cmd: VirtioConsoleControl = match mem.read_obj(head.addr) {
                Ok(cmd) => cmd,
                Err(e) => {
                    log::error!(
                    "Failed to read VirtioConsoleControl struct: {e:?}, struct len = {len}, head.len = {head_len}",
                    len = size_of::<VirtioConsoleControl>(),
                    head_len = head.len,
                );
                    continue;
                }
            };
            if let Err(e) = tx_queue.add_used(mem, head.index, size_of_val(&cmd) as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }

            log::trace!("VirtioConsoleControl cmd: {cmd:?}");
            match cmd.event {
                control_event::VIRTIO_CONSOLE_DEVICE_READY => {
                    log::debug!(
                        "Device is ready: initialization {}",
                        if cmd.value == 1 { "ok" } else { "failed" }
                    );
                    for port_id in 0..self.ports.len() {
                        self.control.port_add(port_id as u32);
                    }
                    if let Err(e) = self.console_ready_evt.write(1) {
                        warn!("Failed to trigger console_ready_evt: {e:?}");
                    }
                    self.console_ready_evt.write(1).unwrap();
                    self.ready = true;
                }
                control_event::VIRTIO_CONSOLE_PORT_READY => {
                    if cmd.value != 1 {
                        log::error!("Port initialization failed: {cmd:?}");
                        continue;
                    }

                    if let Some(term) = self.ports[cmd.id as usize].terminal() {
                        self.control.mark_console_port(mem, cmd.id);
                        self.control.port_open(cmd.id, true);
                        let (cols, rows) = term.get_win_size();
                        self.control
                            .console_resize(cmd.id, VirtioConsoleResize { cols, rows });
                    } else {
                        // We start with all ports open, this makes sense for now,
                        // because underlying file descriptors STDIN, STDOUT, STDERR are always open too
                        self.control.port_open(cmd.id, true)
                    }

                    let name = self.ports[cmd.id as usize].name();
                    log::trace!("Port ready {id}: {name}", id = cmd.id);
                    if !name.is_empty() {
                        self.control.port_name(cmd.id, name)
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_OPEN => {
                    let opened = match cmd.value {
                        0 => false,
                        1 => true,
                        _ => {
                            log::error!(
                                "Invalid value ({}) for VIRTIO_CONSOLE_PORT_OPEN on port {}",
                                cmd.value,
                                cmd.id
                            );
                            continue;
                        }
                    };

                    if opened {
                        ports_to_start.push(cmd.id);
                    } else if let Some(port) = self.ports.get_mut(cmd.id as usize) {
                        log::debug!("Guest closed port {}", cmd.id);
                        port.shutdown();
                        // TODO: close the underlying file descriptors for the port
                        // (note that it requires an API for being able to reopen the ports!)
                    } else {
                        warn!(
                            "Guest tried to close port {} but we don't have such port!",
                            cmd.id
                        );
                    }
                }
                _ => log::warn!("Unknown console control event {:x}", cmd.event),
            }
        }

        for port_id in ports_to_start {
            log::trace!("Starting port io for port {port_id}");
            if let Some(port) = self.ports.get_mut(port_id as usize) {
                port.start(
                    mem.clone(),
                    self.queues[port_id_to_queue_idx(QueueDirection::Rx, port_id as usize)].clone(),
                    self.queues[port_id_to_queue_idx(QueueDirection::Tx, port_id as usize)].clone(),
                    interrupt.clone(),
                    self.control.clone(),
                );
            }
        }

        raise_irq
    }
}

impl VirtioDevice for Console {
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
        uapi::VIRTIO_ID_CONSOLE
    }

    fn device_name(&self) -> &str {
        "console"
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
            "console: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(&mut self, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
            return Err(ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        // Strictly speaking, we should also unsubscribe the queue
        // events, resubscribe the activate eventfd and deactivate
        // the device, but we don't support any scenario in which
        // neither GuestMemory nor the queue events would change,
        // so let's avoid doing any unnecessary work.
        for port in self.ports.iter_mut() {
            port.shutdown();
        }
        self.ready = false;
        true
    }
}

impl VmmExitObserver for Console {
    fn on_vmm_exit(&mut self) {
        self.reset();
        log::trace!("Console on_vmm_exit finished");
    }
}

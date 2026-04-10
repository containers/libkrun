use std::io::IsTerminal;
use std::marker::PhantomData;
use std::os::fd::RawFd;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};

use devices::legacy::IrqChip;
use devices::virtio::{port_io, PortDescription, VirtioDevice, VirtioShmRegion, VmmExitObserver};
use polly::event_manager::{EventManager, Subscriber};
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};
use vmm::builder::{attach_mmio_device, setup_terminal_raw_mode};
use vmm::device_manager::shm::ShmManager;
use vmm::Vmm;

use super::error::{DetailedError, Error};

// ---------------------------------------------------------------------------
// DeviceRequirements — declared by a device before guest memory is created
// ---------------------------------------------------------------------------

/// Requirements a device declares before the VM's memory layout is fixed.
/// `#[non_exhaustive]` allows adding new fields in minor releases.
#[derive(Default)]
#[non_exhaustive]
pub struct DeviceRequirements {
    /// Size of shared memory (DAX) window needed, if any.
    pub shm_size: Option<usize>,
}

// ---------------------------------------------------------------------------
// AttachContext — VMM capabilities provided to devices during attachment
// ---------------------------------------------------------------------------

/// Context provided to devices during attachment.
///
/// This struct wraps internal VMM state and exposes a stable set of capability
/// methods. Adding new methods is a non-breaking (semver-minor) change.
/// Devices call these methods in their [`AttachDevice::attach`] implementation
/// instead of interacting with VMM internals directly.
pub struct AttachContext<'a> {
    vmm: &'a mut Vmm,
    event_manager: &'a mut EventManager,
    shm_manager: &'a ShmManager,
    intc: IrqChip,
    device_index: usize,
    register_fn: Box<
        dyn Fn(&mut Vmm, String, IrqChip, Arc<Mutex<dyn VirtioDevice>>) -> Result<(), DetailedError>
            + 'a,
    >,
}

impl<'a> AttachContext<'a> {
    pub(crate) fn new_mmio(
        vmm: &'a mut Vmm,
        event_manager: &'a mut EventManager,
        shm_manager: &'a ShmManager,
        intc: IrqChip,
        device_index: usize,
    ) -> Self {
        Self {
            vmm,
            event_manager,
            shm_manager,
            intc,
            device_index,
            register_fn: Box::new(|vmm, id, intc, device| {
                attach_mmio_device(vmm, id, intc, device)
                    .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))?;
                Ok(())
            }),
        }
    }

    /// Register a virtio device on the transport bus.
    ///
    /// The actual transport (MMIO, future PCIe) is determined by which
    /// [`DeviceManager`] the device was added to.
    pub fn register(
        &mut self,
        id: &str,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<(), DetailedError> {
        (self.register_fn)(self.vmm, id.to_string(), self.intc.clone(), device)
    }

    /// Subscribe a device to the event loop for epoll-based I/O.
    pub fn subscribe_events(
        &mut self,
        subscriber: Arc<Mutex<dyn Subscriber>>,
    ) -> Result<(), DetailedError> {
        self.event_manager
            .add_subscriber(subscriber)
            .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))
    }

    /// Register a cleanup callback invoked on VM shutdown.
    pub fn push_exit_observer(&mut self, observer: Arc<Mutex<dyn VmmExitObserver>>) {
        self.vmm.exit_observers.push(observer);
    }

    /// The VM's exit code. Devices (e.g. virtiofs) can write to this
    /// to communicate an exit code to the host.
    pub fn exit_code(&self) -> &Arc<AtomicI32> {
        &self.vmm.exit_code
    }

    /// The VM's guest memory map.
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.vmm.guest_memory
    }

    /// The resolved SHM region for the current device index, if one was
    /// allocated based on [`DeviceRequirements::shm_size`].
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    pub fn resolved_shm_region(&self) -> Option<ResolvedShmRegion> {
        self.shm_manager.fs_region(self.device_index).map(|r| {
            let host_addr = self
                .vmm
                .guest_memory
                .get_host_address(r.guest_addr)
                .expect("shm region host address");
            ResolvedShmRegion {
                host_addr: host_addr as u64,
                guest_addr: r.guest_addr.raw_value(),
                size: r.size,
            }
        })
    }

    /// The index of the current device within its device manager.
    pub fn device_index(&self) -> usize {
        self.device_index
    }

    /// Register a SIGWINCH signal handler that writes to the given fd.
    /// Typically used by the console device.
    #[cfg(target_os = "linux")]
    pub fn register_sigwinch(&mut self, fd: RawFd) -> Result<(), DetailedError> {
        vmm::signal_handler::register_sigwinch_handler(fd)
            .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))
    }

    /// Set up terminal raw mode for the given fd, registering a cleanup
    /// observer to restore the terminal on VM shutdown.
    pub fn setup_terminal_raw_mode(&mut self, fd: BorrowedFd<'_>) {
        setup_terminal_raw_mode(self.vmm, Some(fd), false);
    }
}

/// A resolved shared memory region with host and guest addresses.
pub struct ResolvedShmRegion {
    pub host_addr: u64,
    pub guest_addr: u64,
    pub size: usize,
}

impl From<ResolvedShmRegion> for VirtioShmRegion {
    fn from(r: ResolvedShmRegion) -> Self {
        VirtioShmRegion {
            host_addr: r.host_addr,
            guest_addr: r.guest_addr,
            size: r.size,
        }
    }
}

// ---------------------------------------------------------------------------
// AttachDevice trait — how a device attaches itself to a VM
// ---------------------------------------------------------------------------

/// Trait implemented by devices that can be attached to a VM.
///
/// Built-in devices (`FsDevice`, `ConsoleDevice`, etc.) implement this.
/// Future users can implement this for custom virtio devices.
///
/// The [`attach`](AttachDevice::attach) method receives an [`AttachContext`]
/// with all VMM capabilities. Adding new methods to `AttachContext` is a
/// non-breaking change, so the trait signature never needs to change.
pub trait AttachDevice<'a>: Send + 'a {
    /// Declare requirements before guest memory is created.
    fn requirements(&self) -> DeviceRequirements {
        DeviceRequirements::default()
    }

    /// Attach this device to the VM.
    ///
    /// The device should:
    /// 1. Perform any device-specific setup using `ctx` methods
    /// 2. Call [`ctx.register()`](AttachContext::register) to register on the transport bus
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), DetailedError>;
}

// ---------------------------------------------------------------------------
// DeviceManager — sealed trait for transport bus managers
// ---------------------------------------------------------------------------

mod sealed {
    pub trait Sealed {}
}

/// A device manager that owns a set of devices and knows how to attach them
/// to a VM using a specific transport (e.g. MMIO, future PCIe).
///
/// This trait is sealed — only libkrun-provided managers can implement it.
/// The seal may be lifted in a future major version.
pub trait DeviceManager<'a>: sealed::Sealed + Send + 'a {
    /// Collect requirements from all devices (called before guest memory creation).
    #[doc(hidden)]
    fn requirements(&self) -> Vec<DeviceRequirements>;

    /// Attach all devices using the given VMM context.
    #[doc(hidden)]
    fn attach_all(
        self: Box<Self>,
        vmm: &mut Vmm,
        event_manager: &mut EventManager,
        shm_manager: &ShmManager,
        intc: IrqChip,
    ) -> Result<(), DetailedError>;
}

// ---------------------------------------------------------------------------
// MmioDeviceManager — the only DeviceManager for 2.0
// ---------------------------------------------------------------------------

/// Device manager using the virtio-mmio transport.
///
/// Devices added to this manager will be registered on the MMIO bus
/// during VM construction.
pub struct MmioDeviceManager<'a> {
    devices: Vec<Box<dyn AttachDevice<'a> + 'a>>,
}

#[ffier::exportable]
impl<'a> MmioDeviceManager<'a> {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    pub fn add(&mut self, device: impl AttachDevice<'a>) -> &mut Self {
        self.devices.push(Box::new(device));
        self
    }
}

impl sealed::Sealed for MmioDeviceManager<'_> {}

impl<'a> DeviceManager<'a> for MmioDeviceManager<'a> {
    fn requirements(&self) -> Vec<DeviceRequirements> {
        self.devices.iter().map(|d| d.requirements()).collect()
    }

    fn attach_all(
        self: Box<Self>,
        vmm: &mut Vmm,
        event_manager: &mut EventManager,
        shm_manager: &ShmManager,
        intc: IrqChip,
    ) -> Result<(), DetailedError> {
        for (i, device) in self.devices.into_iter().enumerate() {
            let mut ctx = AttachContext::new_mmio(vmm, event_manager, shm_manager, intc.clone(), i);
            device.attach(&mut ctx)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FsDevice
// ---------------------------------------------------------------------------

pub struct FsDevice<'a> {
    pub(crate) inner: Arc<Mutex<devices::virtio::Fs>>,
    #[allow(dead_code)]
    pub(crate) tag: String,
    pub(crate) shm_size: Option<usize>,
    _lifetime: PhantomData<&'a ()>,
}

#[ffier::exportable]
impl<'a> FsDevice<'a> {
    pub fn new(tag: &str, host_path: &str) -> Result<Self, Error> {
        let exit_code = Arc::new(AtomicI32::new(i32::MAX));
        let fs = devices::virtio::Fs::new(
            tag.to_string(),
            host_path.to_string(),
            exit_code.clone(),
            false,
        )
        .map_err(|e| {
            log::error!("fs device: {e:?}");
            Error::Internal
        })?;

        Ok(Self {
            inner: Arc::new(Mutex::new(fs)),
            tag: tag.to_string(),
            shm_size: None,
            _lifetime: PhantomData,
        })
    }

    pub fn set_dax_window_size(&mut self, bytes: u64) {
        self.shm_size = Some(bytes as usize);
    }
}

#[ffier::trait_impl]
impl<'a> AttachDevice<'a> for FsDevice<'a> {
    #[ffier(skip)]
    fn requirements(&self) -> DeviceRequirements {
        DeviceRequirements {
            shm_size: self.shm_size,
        }
    }

    #[ffier(skip)]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), DetailedError> {
        {
            let mut fs = self.inner.lock().unwrap();
            // Wire exit code from VMM into the fs device
            fs.set_exit_code(ctx.exit_code().clone());
            // Set up SHM region if allocated
            if let Some(region) = ctx.resolved_shm_region() {
                fs.set_shm_region(region.into());
            }
        }

        ctx.register(&format!("virtiofs{}", ctx.device_index()), self.inner)
    }
}

// ---------------------------------------------------------------------------
// ConsoleDevice + Builder
// ---------------------------------------------------------------------------

pub struct ConsoleDevice<'a> {
    pub(crate) ports: Vec<PortDescription>,
    #[allow(dead_code)]
    pub(crate) kernel_console_port: Option<u32>,
    /// Raw fds of TTY ports that need raw mode set after Vmm is constructed.
    pub(crate) tty_fds: Vec<i32>,
    _lifetime: PhantomData<&'a ()>,
}

pub struct ConsoleBuilder<'a> {
    ports: Vec<PortDescription>,
    kernel_console_port: Option<u32>,
    tty_fds: Vec<i32>,
    _lifetime: PhantomData<&'a ()>,
}

#[ffier::exportable]
impl<'a> ConsoleDevice<'a> {
    pub fn builder() -> ConsoleBuilder<'a> {
        ConsoleBuilder {
            ports: Vec::new(),
            kernel_console_port: None,
            tty_fds: Vec::new(),
            _lifetime: PhantomData,
        }
    }
}

#[ffier::exportable]
impl<'a> ConsoleBuilder<'a> {
    pub fn add_tty_port(&mut self, name: &str, tty_fd: BorrowedFd<'a>) -> Result<u32, Error> {
        let index = self.ports.len() as u32;
        self.add_tty_port_inner(name, tty_fd)?;
        Ok(index)
    }

    pub fn set_kernel_console(&mut self, port_index: u32) -> Result<(), Error> {
        if port_index as usize >= self.ports.len() {
            return Err(Error::OutOfRange);
        }
        self.kernel_console_port = Some(port_index);
        Ok(())
    }

    pub fn build(self) -> Result<ConsoleDevice<'a>, Error> {
        if self.ports.is_empty() {
            return Err(Error::MissingConfig);
        }
        Ok(ConsoleDevice {
            ports: self.ports,
            kernel_console_port: self.kernel_console_port,
            tty_fds: self.tty_fds,
            _lifetime: PhantomData,
        })
    }
}

impl ConsoleBuilder<'_> {
    /// Add an output-only port (no input, no terminal).
    pub(crate) fn add_output_port(
        &mut self,
        name: &str,
        output: Box<dyn devices::virtio::port_io::PortOutput + Send>,
    ) -> u32 {
        let index = self.ports.len() as u32;
        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input: None,
            output: Some(output),
            terminal: None,
        });
        index
    }

    /// Add an output-only console port with fake terminal properties.
    pub(crate) fn add_console_port(
        &mut self,
        name: &str,
        output: Box<dyn devices::virtio::port_io::PortOutput + Send>,
    ) -> u32 {
        let index = self.ports.len() as u32;
        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input: None,
            output: Some(output),
            terminal: Some(port_io::term_fixed_size(80, 24)),
        });
        index
    }

    /// Add a port with separate input and output fds (no terminal properties).
    pub(crate) fn add_io_port(
        &mut self,
        name: &str,
        input_fd: Option<i32>,
        output_fd: Option<i32>,
    ) -> Result<u32, Error> {
        let index = self.ports.len() as u32;
        let input = match input_fd {
            Some(fd) if fd >= 0 => Some(port_io::input_to_raw_fd_dup(fd).map_err(|e| {
                log::error!("dup input fd: {e}");
                Error::BadFd
            })?),
            _ => None,
        };
        let output = match output_fd {
            Some(fd) if fd >= 0 => Some(port_io::output_to_raw_fd_dup(fd).map_err(|e| {
                log::error!("dup output fd: {e}");
                Error::BadFd
            })?),
            _ => None,
        };
        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input,
            output,
            terminal: None,
        });
        Ok(index)
    }

    fn add_tty_port_inner(&mut self, name: &str, tty_fd: BorrowedFd<'_>) -> Result<(), Error> {
        let raw_fd = tty_fd.as_raw_fd();

        let input = Some(port_io::input_to_raw_fd_dup(raw_fd).map_err(|e| {
            log::error!("dup input fd: {e}");
            Error::BadFd
        })?);
        let output = Some(port_io::output_to_raw_fd_dup(raw_fd).map_err(|e| {
            log::error!("dup output fd: {e}");
            Error::BadFd
        })?);

        let file_check = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        let is_term = file_check.is_terminal();
        std::mem::forget(file_check);
        let terminal: Option<Box<dyn devices::virtio::port_io::PortTerminalProperties>> = if is_term
        {
            Some(port_io::term_fd(raw_fd).map_err(|e| {
                log::error!("term fd: {e}");
                Error::BadFd
            })?)
        } else {
            None
        };

        if is_term {
            self.tty_fds.push(raw_fd);
        }

        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input,
            output,
            terminal,
        });
        Ok(())
    }
}

#[ffier::trait_impl]
impl<'a> AttachDevice<'a> for ConsoleDevice<'a> {
    #[ffier(skip)]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), DetailedError> {
        let tty_fds = self.tty_fds.clone();

        let console_dev = Arc::new(Mutex::new(
            devices::virtio::Console::new(self.ports)
                .map_err(|e| DetailedError::new(Error::Internal, format!("console: {e:?}")))?,
        ));

        ctx.push_exit_observer(console_dev.clone());
        ctx.subscribe_events(console_dev.clone())?;

        #[cfg(target_os = "linux")]
        ctx.register_sigwinch(console_dev.lock().unwrap().get_sigwinch_fd())?;

        ctx.register(&format!("hvc{}", ctx.device_index()), console_dev)?;

        for fd in &tty_fds {
            let borrowed = unsafe { BorrowedFd::borrow_raw(*fd) };
            ctx.setup_terminal_raw_mode(borrowed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BalloonDevice
// ---------------------------------------------------------------------------

pub struct BalloonDevice {
    pub(crate) inner: Arc<Mutex<devices::virtio::Balloon>>,
}

#[ffier::exportable]
impl BalloonDevice {
    pub fn new() -> Result<Self, Error> {
        let balloon = devices::virtio::Balloon::new().map_err(|e| {
            log::error!("balloon: {e:?}");
            Error::Internal
        })?;
        Ok(Self {
            inner: Arc::new(Mutex::new(balloon)),
        })
    }
}

#[ffier::trait_impl]
impl<'a> AttachDevice<'a> for BalloonDevice {
    #[ffier(skip)]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), DetailedError> {
        ctx.subscribe_events(self.inner.clone())?;
        ctx.register("balloon", self.inner)
    }
}

// ---------------------------------------------------------------------------
// RngDevice
// ---------------------------------------------------------------------------

pub struct RngDevice {
    pub(crate) inner: Arc<Mutex<devices::virtio::Rng>>,
}

#[ffier::exportable]
impl RngDevice {
    pub fn new() -> Result<Self, Error> {
        let rng = devices::virtio::Rng::new().map_err(|e| {
            log::error!("rng: {e:?}");
            Error::Internal
        })?;
        Ok(Self {
            inner: Arc::new(Mutex::new(rng)),
        })
    }
}

#[ffier::trait_impl]
impl<'a> AttachDevice<'a> for RngDevice {
    #[ffier(skip)]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), DetailedError> {
        ctx.subscribe_events(self.inner.clone())?;
        ctx.register("rng", self.inner)
    }
}

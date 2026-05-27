use std::marker::PhantomData;
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};

use devices::legacy::{IrqChip, IrqChipDevice};
use kernel::cmdline::Cmdline;
use polly::event_manager::EventManager;
use utils::eventfd::EventFd;
use vmm::builder::{self, choose_payload, create_guest_memory, load_cmdline};
use vmm::device_manager::mmio::MMIODeviceManager;
use vmm::vstate::VcpuConfig;
use vmm::Vmm as InnerVmm;

use super::devices::{DeviceManager, MmioDeviceManager};
use super::error::{DetailedError, Error};
use super::payload::{KrunPayload, Payload};

// ---------------------------------------------------------------------------
// VmmBuilder
// ---------------------------------------------------------------------------

pub struct VmmBuilder<'a> {
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    payload: Option<Box<dyn KrunPayload>>,
    device_manager: Option<Box<dyn DeviceManager<'a> + 'a>>,
}

#[ffier::exportable]
impl<'a> VmmBuilder<'a> {
    pub fn new() -> Self {
        VmmBuilder {
            vcpus: None,
            ram_mib: None,
            payload: None,
            device_manager: None,
        }
    }

    pub fn vcpus(mut self, count: u8) -> Result<Self, Error> {
        if count == 0 {
            return Err(Error::OutOfRange);
        }
        self.vcpus = Some(count);
        Ok(self)
    }

    pub fn ram_mib(mut self, mib: u32) -> Result<Self, Error> {
        if mib == 0 {
            return Err(Error::OutOfRange);
        }
        self.ram_mib = Some(mib);
        Ok(self)
    }

    pub fn payload(mut self, payload: impl Payload) -> Self {
        self.payload = Some(payload.into_payload());
        self
    }

    pub fn devices(mut self, devices: MmioDeviceManager<'a>) -> Self {
        self.device_manager = Some(Box::new(devices));
        self
    }

    pub fn build(self) -> Result<Vmm<'a>, Error> {
        build_vm(self).map_err(|e| {
            log::error!("{e}");
            e.code
        })
    }
}

// ---------------------------------------------------------------------------
// Vmm — the running VM handle
// ---------------------------------------------------------------------------

pub struct Vmm<'a> {
    #[allow(dead_code)]
    inner: Arc<Mutex<InnerVmm>>,
    event_manager: EventManager,
    _lifetime: PhantomData<&'a ()>,
}

#[ffier::exportable]
impl<'a> Vmm<'a> {
    pub fn run(&mut self) {
        loop {
            if let Err(e) = self.event_manager.run() {
                log::error!("fatal event loop error: {e:?}");
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The actual VM construction logic
// ---------------------------------------------------------------------------

fn build_vm(builder_cfg: VmmBuilder<'_>) -> Result<Vmm<'_>, DetailedError> {
    let vcpus_count = builder_cfg
        .vcpus
        .ok_or_else(|| DetailedError::new(Error::MissingConfig, "vcpus not set"))?;
    let ram_mib = builder_cfg
        .ram_mib
        .ok_or_else(|| DetailedError::new(Error::MissingConfig, "ram_mib not set"))?;
    let payload = builder_cfg
        .payload
        .ok_or_else(|| DetailedError::new(Error::MissingConfig, "payload not set"))?;
    let device_manager = builder_cfg.device_manager.ok_or_else(|| {
        DetailedError::new(
            Error::MissingConfig,
            "no device manager set (call .devices())",
        )
    })?;

    // 1. Load kernel (payload-specific: krunfw, external kernel, etc.)
    let kernel_bundle = payload.load_kernel()?;

    // 2. Choose payload type
    let payload_type = choose_payload(
        Some(&kernel_bundle),
        #[cfg(feature = "tee")]
        None,
        #[cfg(feature = "tee")]
        None,
        None, // external_kernel
        None, // firmware_config
    )
    .map_err(|e| DetailedError::new(Error::BootError, format!("{e:?}")))?;

    // 3. Collect shm sizes from device manager requirements
    let requirements = device_manager.requirements();
    let fs_shm_sizes: Vec<Option<usize>> = requirements.iter().map(|r| r.shm_size).collect();

    #[cfg(feature = "gpu")]
    let (gpu_virgl_flags, gpu_shm_size) = {
        let gpu_req = requirements.iter().find_map(|r| r.gpu_shm.as_ref());
        match gpu_req {
            Some(req) => (Some(req.virgl_flags), Some(req.shm_size)),
            None => (None, None),
        }
    };
    #[cfg(not(feature = "gpu"))]
    let (gpu_virgl_flags, gpu_shm_size): (Option<u32>, Option<usize>) = (None, None);

    // 4. Create guest memory
    let (guest_memory, arch_memory_info, shm_manager, payload_config) = create_guest_memory(
        ram_mib as usize,
        Some(&kernel_bundle),
        #[cfg(feature = "tee")]
        None,
        #[cfg(feature = "tee")]
        None,
        None, // firmware_config
        &fs_shm_sizes,
        gpu_virgl_flags,
        gpu_shm_size,
        &payload_type,
    )
    .map_err(|e| DetailedError::new(Error::BootError, format!("{e:?}")))?;

    // 5. Build kernel command line (payload-specific base + env vars)
    let mut kernel_cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE);

    if let Some(cmdline) = payload_config.kernel_cmdline {
        kernel_cmdline.insert_str(cmdline.as_str()).unwrap();
    } else {
        payload.configure_cmdline(&mut kernel_cmdline)?;
    }

    log::info!("kernel cmdline: {}", kernel_cmdline.as_str());
    log::info!(
        "kernel bundle: host=0x{:x} guest=0x{:x} entry=0x{:x} size={}",
        kernel_bundle.host_addr,
        kernel_bundle.guest_addr,
        kernel_bundle.entry_addr,
        kernel_bundle.size
    );
    log::info!("payload entry_addr: 0x{:x}", payload_config.entry_addr.0);
    log::info!(
        "mem_info: ram_below_gap={} ram_above_gap={} ram_last_addr=0x{:x}",
        arch_memory_info.ram_below_gap,
        arch_memory_info.ram_above_gap,
        arch_memory_info.ram_last_addr
    );

    // 6. Set up VM
    #[cfg(not(feature = "tee"))]
    let vm = builder::setup_vm(&guest_memory, false)
        .map_err(|e| DetailedError::new(Error::HypervisorError, format!("{e:?}")))?;

    let mut event_manager = EventManager::new()
        .map_err(|e| DetailedError::new(Error::Internal, format!("EventManager: {e:?}")))?;

    // 7. Create legacy serial device on COM1 (no output — kernel console goes via hvc0)
    let serial_devices = vec![builder::setup_serial_device(&mut event_manager, None, None)
        .map_err(|e| DetailedError::new(Error::Internal, format!("serial: {e:?}")))?];

    let exit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK)
        .map_err(|e| DetailedError::new(Error::Internal, format!("eventfd: {e}")))?;

    // 8. Create internal device managers (MMIO bus, PIO bus)
    #[cfg(target_arch = "x86_64")]
    let mut pio_device_manager = {
        use devices::legacy::Cmos;
        vmm::device_manager::legacy::PortIODeviceManager::new(
            Arc::new(Mutex::new(Cmos::new(
                arch_memory_info.ram_below_gap,
                arch_memory_info.ram_above_gap,
            ))),
            serial_devices,
            exit_evt
                .try_clone()
                .map_err(|e| DetailedError::new(Error::Internal, format!("eventfd: {e}")))?,
        )
        .map_err(|e| DetailedError::new(Error::Internal, format!("pio: {e:?}")))?
    };

    #[allow(unused_mut)]
    let mut mmio_device_manager = MMIODeviceManager::new(
        &mut (arch::MMIO_MEM_START.clone()),
        (arch::IRQ_BASE, arch::IRQ_MAX),
    );

    let vcpu_config = VcpuConfig {
        vcpu_count: vcpus_count,
        ht_enabled: false,
        cpu_template: None,
    };

    // 9. Create vCPUs + interrupt controller (arch-specific)
    let vcpus;
    let intc: IrqChip;

    #[cfg(target_arch = "x86_64")]
    {
        use devices::legacy::KvmIoapic;

        let ioapic = Box::new(
            KvmIoapic::new(vm.fd())
                .map_err(|e| DetailedError::new(Error::HypervisorError, format!("{e:?}")))?,
        );
        intc = Arc::new(Mutex::new(IrqChipDevice::new(ioapic)));

        builder::attach_legacy_devices(
            &vm,
            false, // split_irqchip
            &mut pio_device_manager,
            &mut mmio_device_manager,
            Some(intc.clone()),
        )
        .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))?;

        vcpus = builder::create_vcpus_x86_64(
            &vm,
            &vcpu_config,
            &guest_memory,
            payload_config.entry_addr,
            &pio_device_manager.io_bus,
            &exit_evt,
            true, // kernel_boot
            #[cfg(feature = "tee")]
            crossbeam_channel::unbounded().0,
        )
        .map_err(|e| DetailedError::new(Error::HypervisorError, format!("{e:?}")))?;
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        use devices::legacy::{KvmGicV2, KvmGicV3};

        vcpus = builder::create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
            payload_config.entry_addr,
            &exit_evt,
        )
        .map_err(|e| DetailedError::new(Error::HypervisorError, format!("{e:?}")))?;

        intc = {
            let gic = match KvmGicV3::new(vm.fd(), vcpus_count as u64) {
                Ok(gicv3) => IrqChipDevice::new(Box::new(gicv3)),
                Err(_) => IrqChipDevice::new(Box::new(KvmGicV2::new(vm.fd(), vcpus_count as u64))),
            };
            Arc::new(Mutex::new(gic))
        };

        builder::attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
        )
        .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))?;
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        use devices::legacy::{GicV3, HvfGicV3, VcpuList};

        let vcpu_list = Arc::new(VcpuList::new(vcpus_count as u64));

        intc = {
            let gic = match HvfGicV3::new(vcpus_count as u64) {
                Ok(hvfgic) => IrqChipDevice::new(Box::new(hvfgic)),
                Err(_) => IrqChipDevice::new(Box::new(GicV3::new(vcpu_list.clone()))),
            };
            Arc::new(Mutex::new(gic))
        };

        vcpus = builder::create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
            payload_config.entry_addr,
            &exit_evt,
            vcpu_list.clone(),
            false, // nested_enabled
        )
        .map_err(|e| DetailedError::new(Error::HypervisorError, format!("{e:?}")))?;

        builder::attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
            &mut event_manager,
            None, // shutdown_efd
        )
        .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))?;
    }

    // 10. Construct Vmm struct
    let exit_code = Arc::new(AtomicI32::new(i32::MAX));

    let mut vmm = InnerVmm {
        guest_memory,
        arch_memory_info,
        kernel_cmdline,
        vcpus_handles: Vec::new(),
        exit_evt,
        exit_observers: Vec::new(),
        exit_code: exit_code.clone(),
        vm,
        mmio_device_manager,
        #[cfg(target_arch = "x86_64")]
        pio_device_manager,
    };

    // 11. Create worker thread channel (used for macOS GPU mapping, x86 GSI, TEE)
    #[allow(unused_variables)]
    let (worker_sender, worker_receiver) = crossbeam_channel::unbounded();

    // 12. Attach all devices via the device manager
    device_manager.attach_all(
        &mut vmm,
        &mut event_manager,
        &shm_manager,
        intc.clone(),
        #[cfg(target_os = "macos")]
        Some(worker_sender),
    )?;

    // 12. Append "-- args" epilog (must come after device attachment,
    //     because MMIO device params are appended to the cmdline during
    //     registration and must come BEFORE "--").
    let epilog = payload.cmdline_epilog();
    if !epilog.is_empty() {
        vmm.kernel_cmdline
            .insert_str(&format!(" -- {epilog}"))
            .unwrap();
    }

    log::info!("final cmdline: {}", vmm.kernel_cmdline.as_str());

    // 13. Write kernel cmdline to guest memory (x86_64)
    #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
    load_cmdline(&vmm).map_err(|e| DetailedError::new(Error::BootError, format!("{e:?}")))?;

    // 14. Configure system
    vmm.configure_system(
        vcpus.as_slice(),
        &intc,
        &payload_config.initrd_config,
        &None, // smbios_oem_strings
    )
    .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))?;

    // 15. Start vCPUs
    vmm.start_vcpus(vcpus)
        .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))?;

    // 16. Register with EventManager and start worker thread
    #[allow(clippy::arc_with_non_send_sync)]
    let vmm = Arc::new(Mutex::new(vmm));
    event_manager
        .add_subscriber(vmm.clone())
        .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))?;

    // Start the VMM worker thread. It processes messages from devices that
    // need VMM-level operations (macOS GPU memory mapping, x86_64 GSI routing,
    // TEE memory conversion).
    vmm::worker::start_worker_thread(vmm.clone(), worker_receiver)
        .map_err(|e| DetailedError::new(Error::Internal, format!("worker thread: {e}")))?;

    Ok(Vmm {
        inner: vmm,
        event_manager,
        _lifetime: PhantomData,
    })
}

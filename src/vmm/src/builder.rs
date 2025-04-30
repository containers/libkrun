// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enables pre-boot setup, instantiation and booting of a Firecracker VMM.

#[cfg(target_os = "macos")]
use crossbeam_channel::unbounded;
use crossbeam_channel::Sender;
use kernel::cmdline::Cmdline;
#[cfg(target_os = "macos")]
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, Read};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};

use super::{Error, Vmm};

#[cfg(target_arch = "x86_64")]
use crate::device_manager::legacy::PortIODeviceManager;
use crate::device_manager::mmio::MMIODeviceManager;
use crate::resources::VmResources;
use crate::vmm_config::external_kernel::{ExternalKernel, KernelFormat};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use devices::legacy::KvmGicV3;
#[cfg(target_arch = "x86_64")]
use devices::legacy::KvmIoapic;
use devices::legacy::Serial;
#[cfg(target_os = "macos")]
use devices::legacy::VcpuList;
#[cfg(target_os = "macos")]
use devices::legacy::{GicV3, HvfGicV3};
#[cfg(target_arch = "x86_64")]
use devices::legacy::{IoApic, IrqChipT};
use devices::legacy::{IrqChip, IrqChipDevice};
#[cfg(feature = "net")]
use devices::virtio::Net;
use devices::virtio::{port_io, MmioTransport, PortDescription, Vsock};

#[cfg(feature = "tee")]
use kbs_types::Tee;

use crate::device_manager;
#[cfg(feature = "tee")]
use crate::resources::TeeConfig;
#[cfg(target_os = "linux")]
use crate::signal_handler::register_sigint_handler;
#[cfg(target_os = "linux")]
use crate::signal_handler::register_sigwinch_handler;
use crate::terminal::term_set_raw_mode;
#[cfg(feature = "blk")]
use crate::vmm_config::block::BlockBuilder;
use crate::vmm_config::boot_source::DEFAULT_KERNEL_CMDLINE;
#[cfg(not(feature = "tee"))]
use crate::vmm_config::fs::FsDeviceConfig;
#[cfg(target_os = "linux")]
use crate::vstate::KvmContext;
#[cfg(all(target_os = "linux", feature = "tee"))]
use crate::vstate::MeasuredRegion;
use crate::vstate::{Error as VstateError, Vcpu, VcpuConfig, Vm};
use arch::{ArchMemoryInfo, InitrdConfig};
use device_manager::shm::ShmManager;
#[cfg(not(feature = "tee"))]
use devices::virtio::{fs::ExportTable, VirtioShmRegion};
use flate2::read::GzDecoder;
#[cfg(feature = "tee")]
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
#[cfg(target_arch = "x86_64")]
use linux_loader::loader::{self, KernelLoader};
use nix::unistd::isatty;
use polly::event_manager::{Error as EventManagerError, EventManager};
use utils::eventfd::EventFd;
use utils::worker_message::WorkerMessage;
#[cfg(all(target_arch = "x86_64", not(feature = "efi"), not(feature = "tee")))]
use vm_memory::mmap::MmapRegion;
#[cfg(not(feature = "tee"))]
use vm_memory::Address;
use vm_memory::Bytes;
#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
use vm_memory::GuestRegionMmap;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

#[cfg(feature = "efi")]
static EDK2_BINARY: &[u8] = include_bytes!("../../../edk2/KRUN_EFI.silent.fd");

/// Errors associated with starting the instance.
#[derive(Debug)]
pub enum StartMicrovmError {
    /// Unable to attach block device to Vmm.
    AttachBlockDevice(io::Error),
    #[cfg(target_os = "macos")]
    /// Failed to create HVF in-kernel IrqChip.
    CreateHvfIrqChip(hvf::Error),
    #[cfg(target_os = "linux")]
    /// Failed to create KVM in-kernel IrqChip.
    CreateKvmIrqChip(kvm_ioctls::Error),
    /// Failed to create a `RateLimiter` object.
    CreateRateLimiter(io::Error),
    /// Cannot open the file containing the kernel code.
    ElfOpenKernel(io::Error),
    /// Cannot load the kernel into the VM.
    ElfLoadKernel(linux_loader::loader::Error),
    /// Memory regions are overlapping or mmap fails.
    GuestMemoryMmap(vm_memory::Error),
    /// The BZIP2 decoder couldn't decompress the kernel.
    ImageBz2Decoder(io::Error),
    /// Cannot find compressed kernel in file.
    ImageBz2Invalid,
    /// Cannot load the kernel from the uncompressed ELF data.
    ImageBz2LoadKernel(linux_loader::loader::Error),
    /// Cannot open the file containing the kernel code.
    ImageBz2OpenKernel(io::Error),
    /// The GZIP decoder couldn't decompress the kernel.
    ImageGzDecoder(io::Error),
    /// Cannot find compressed kernel in file.
    ImageGzInvalid,
    /// Cannot load the kernel from the uncompressed ELF data.
    ImageGzLoadKernel(linux_loader::loader::Error),
    /// Cannot open the file containing the kernel code.
    ImageGzOpenKernel(io::Error),
    /// The ZSTD decoder couldn't decompress the kernel.
    ImageZstdDecoder(io::Error),
    /// Cannot find compressed kernel in file.
    ImageZstdInvalid,
    /// Cannot load the kernel from the uncompressed ELF data.
    ImageZstdLoadKernel(linux_loader::loader::Error),
    /// Cannot open the file containing the kernel code.
    ImageZstdOpenKernel(io::Error),
    /// Cannot load initrd due to an invalid memory configuration.
    InitrdLoad,
    /// Cannot load initrd due to an invalid image.
    InitrdRead(io::Error),
    /// Internal error encountered while starting a microVM.
    Internal(Error),
    /// Cannot inject the kernel into the guest memory due to a problem with the bundle.
    InvalidKernelBundle(vm_memory::mmap::MmapRegionError),
    /// The kernel command line is invalid.
    KernelCmdline(String),
    /// The supplied kernel format is not supported.
    KernelFormatUnsupported,
    /// Cannot load command line string.
    LoadCommandline(kernel::cmdline::Error),
    /// The start command was issued more than once.
    MicroVMAlreadyRunning,
    /// Cannot start the VM because the kernel was not configured.
    MissingKernelConfig,
    /// Cannot start the VM because the size of the guest memory  was not specified.
    MissingMemSizeConfig,
    /// The net device configuration is missing the tap device.
    NetDeviceNotConfigured,
    /// Cannot open the block device backing file.
    OpenBlockDevice(io::Error),
    /// Cannot open console output file.
    OpenConsoleFile(io::Error),
    /// The GZIP decoder couldn't decompress the kernel.
    PeGzDecoder(io::Error),
    /// Cannot open the file containing the kernel code.
    PeGzOpenKernel(io::Error),
    /// Cannot find compressed kernel in file.
    PeGzInvalid,
    /// Cannot open the file containing the kernel code.
    RawOpenKernel(io::Error),
    /// Cannot initialize a MMIO Balloon device or add a device to the MMIO Bus.
    RegisterBalloonDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Block Device or add a device to the MMIO Bus.
    RegisterBlockDevice(device_manager::mmio::Error),
    /// Cannot register an EventHandler.
    RegisterEvent(EventManagerError),
    /// Cannot initialize a MMIO Fs Device or add ad device to the MMIO Bus.
    RegisterFsDevice(device_manager::mmio::Error),
    /// Cannot register SIGWINCH event file descriptor.
    #[cfg(target_os = "linux")]
    RegisterFsSigwinch(kvm_ioctls::Error),
    /// Cannot initialize a MMIO Gpu device or add a device to the MMIO Bus.
    RegisterGpuDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Network Device or add a device to the MMIO Bus.
    RegisterNetDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Rng device or add a device to the MMIO Bus.
    RegisterRngDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Snd device or add a device to the MMIO Bus.
    RegisterSndDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Vsock Device or add a device to the MMIO Bus.
    RegisterVsockDevice(device_manager::mmio::Error),
    /// Cannot attest the VM in the Secure Virtualization context.
    SecureVirtAttest(VstateError),
    /// Cannot initialize the Secure Virtualization backend.
    SecureVirtPrepare(VstateError),
    /// Error configuring an SHM region.
    ShmConfig(device_manager::shm::Error),
    /// Error creating an SHM region.
    ShmCreate(device_manager::shm::Error),
    /// Error obtaining the host address of an SHM region.
    ShmHostAddr(vm_memory::GuestMemoryError),
    /// The TEE specified is not supported.
    InvalidTee,
}

/// It's convenient to automatically convert `kernel::cmdline::Error`s
/// to `StartMicrovmError`s.
impl std::convert::From<kernel::cmdline::Error> for StartMicrovmError {
    fn from(e: kernel::cmdline::Error) -> StartMicrovmError {
        StartMicrovmError::KernelCmdline(e.to_string())
    }
}

impl Display for StartMicrovmError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::StartMicrovmError::*;
        match *self {
            AttachBlockDevice(ref err) => {
                write!(f, "Unable to attach block device to Vmm. Error: {err}")
            }
            #[cfg(target_os = "macos")]
            CreateHvfIrqChip(ref err) => {
                write!(f, "Cannot create HVF in-kernel IrqChip: {err}")
            }
            #[cfg(target_os = "linux")]
            CreateKvmIrqChip(ref err) => {
                write!(f, "Cannot create KVM in-kernel IrqChip: {err}")
            }
            CreateRateLimiter(ref err) => write!(f, "Cannot create RateLimiter: {err}"),
            ElfOpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code: {err}")
            }
            ElfLoadKernel(ref err) => {
                write!(f, "Cannot load the kernel into the VM: {err}")
            }
            GuestMemoryMmap(ref err) => {
                // Remove imbricated quotes from error message.
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");
                write!(f, "Invalid Memory Configuration: {err_msg}")
            }
            ImageBz2Decoder(ref err) => {
                write!(f, "The BZIP2 decoder couldn't decompress the kernel. {err}")
            }
            ImageBz2Invalid => {
                write!(f, "Cannot find compressed kernel in file.")
            }
            ImageBz2LoadKernel(ref err) => {
                write!(
                    f,
                    "Cannot load the kernel from the uncompressed ELF data. {err}"
                )
            }
            ImageBz2OpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code. {err}")
            }
            ImageGzDecoder(ref err) => {
                write!(f, "The GZIP decoder couldn't decompress the kernel. {err}")
            }
            ImageGzInvalid => {
                write!(f, "Cannot find compressed kernel in file.")
            }
            ImageGzLoadKernel(ref err) => {
                write!(
                    f,
                    "Cannot load the kernel from the uncompressed ELF data. {err}"
                )
            }
            ImageGzOpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code. {err}")
            }
            ImageZstdDecoder(ref err) => {
                write!(f, "The ZSTD decoder couldn't decompress the kernel. {err}")
            }
            ImageZstdInvalid => {
                write!(f, "Cannot find compressed kernel in file.")
            }
            ImageZstdLoadKernel(ref err) => {
                write!(
                    f,
                    "Cannot load the kernel from the uncompressed ELF data. {err}"
                )
            }
            ImageZstdOpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code. {err}")
            }
            InitrdLoad => write!(
                f,
                "Cannot load initrd due to an invalid memory configuration."
            ),
            InitrdRead(ref err) => write!(f, "Cannot load initrd due to an invalid image: {err}"),
            Internal(ref err) => write!(f, "Internal error while starting microVM: {err:?}"),
            InvalidKernelBundle(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot inject the kernel into the guest memory due to a problem with the \
                     bundle. {err_msg}"
                )
            }
            KernelCmdline(ref err) => write!(f, "Invalid kernel command line: {err}"),
            KernelFormatUnsupported => {
                write!(f, "The supplied kernel format is not supported.")
            }
            LoadCommandline(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(f, "Cannot load command line string. {err_msg}")
            }
            MicroVMAlreadyRunning => write!(f, "Microvm already running."),
            MissingKernelConfig => write!(f, "Cannot start microvm without kernel configuration."),
            MissingMemSizeConfig => {
                write!(f, "Cannot start microvm without guest mem_size config.")
            }
            NetDeviceNotConfigured => {
                write!(f, "The net device configuration is missing the tap device.")
            }
            OpenBlockDevice(ref err) => {
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");

                write!(f, "Cannot open the block device backing file. {err_msg}")
            }
            OpenConsoleFile(ref err) => {
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");

                write!(f, "Cannot open the console output file. {err_msg}")
            }
            PeGzDecoder(ref err) => {
                write!(f, "The GZIP decoder couldn't decompress the kernel. {err}")
            }
            PeGzOpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code. {err}")
            }
            PeGzInvalid => {
                write!(f, "Cannot find compressed kernel in file.")
            }
            RawOpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code: {err}")
            }
            RegisterBalloonDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Balloon Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterBlockDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Block Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterEvent(ref err) => write!(f, "Cannot register EventHandler. {err:?}"),
            RegisterFsDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot initialize a MMIO Fs Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            #[cfg(target_os = "linux")]
            RegisterFsSigwinch(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot register SIGWINCH file descriptor for Fs Device. {err_msg}"
                )
            }
            RegisterGpuDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Gpu Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterNetDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot initialize a MMIO Network Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterRngDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Rng Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterSndDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Snd Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterVsockDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot initialize a MMIO Vsock Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            SecureVirtAttest(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot attest the VM in the Secure Virtualization context. {err_msg}"
                )
            }
            SecureVirtPrepare(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot initialize the Secure Virtualization backend. {err_msg}"
                )
            }
            ShmHostAddr(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Error obtaining the host address of an SHM region. {err_msg}"
                )
            }
            ShmConfig(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace('\"', "");

                write!(f, "Error while configuring an SHM region. {err_msg}")
            }
            ShmCreate(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace('\"', "");

                write!(f, "Error while creating an SHM region. {err_msg}")
            }
            InvalidTee => {
                write!(f, "TEE selected is not currently supported")
            }
        }
    }
}

enum Payload {
    #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
    KernelMmap,
    #[cfg(target_arch = "aarch64")]
    KernelCopy,
    ExternalKernel(ExternalKernel),
    #[cfg(test)]
    Empty,
    Efi,
    #[cfg(feature = "tee")]
    Tee,
}

fn choose_payload(vm_resources: &VmResources) -> Result<Payload, StartMicrovmError> {
    if let Some(_kernel_bundle) = &vm_resources.kernel_bundle {
        #[cfg(feature = "tee")]
        if vm_resources.qboot_bundle.is_none() || vm_resources.initrd_bundle.is_none() {
            return Err(StartMicrovmError::MissingKernelConfig);
        }

        #[cfg(feature = "tee")]
        return Ok(Payload::Tee);

        #[cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "tee")))]
        return Ok(Payload::KernelMmap);

        #[cfg(target_arch = "aarch64")]
        return Ok(Payload::KernelCopy);
    } else if let Some(external_kernel) = vm_resources.external_kernel() {
        Ok(Payload::ExternalKernel(external_kernel.clone()))
    } else if cfg!(feature = "efi") {
        Ok(Payload::Efi)
    } else {
        Err(StartMicrovmError::MissingKernelConfig)
    }
}

/// Builds and starts a microVM based on the current Firecracker VmResources configuration.
///
/// This is the default build recipe, one could build other microVM flavors by using the
/// independent functions in this module instead of calling this recipe.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
pub fn build_microvm(
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    _shutdown_efd: Option<EventFd>,
    _sender: Sender<WorkerMessage>,
) -> std::result::Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    let payload = choose_payload(vm_resources)?;

    let (guest_memory, arch_memory_info, mut _shm_manager, payload_config) = create_guest_memory(
        vm_resources
            .vm_config()
            .mem_size_mib
            .ok_or(StartMicrovmError::MissingMemSizeConfig)?,
        vm_resources,
        &payload,
    )?;
    let vcpu_config = vm_resources.vcpu_config();

    // Clone the command-line so that a failed boot doesn't pollute the original.
    #[allow(unused_mut)]
    let mut kernel_cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE);
    if let Some(cmdline) = payload_config.kernel_cmdline {
        kernel_cmdline.insert_str(cmdline.as_str()).unwrap();
    } else if let Some(cmdline) = &vm_resources.boot_config.kernel_cmdline_prolog {
        kernel_cmdline.insert_str(cmdline).unwrap();
    } else {
        kernel_cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).unwrap();
    }

    #[cfg(not(feature = "tee"))]
    #[allow(unused_mut)]
    let mut vm = setup_vm(&guest_memory, vm_resources.nested_enabled)?;

    #[cfg(feature = "tee")]
    let (kvm, vm) = {
        let kvm = KvmContext::new()
            .map_err(Error::KvmContext)
            .map_err(StartMicrovmError::Internal)?;
        let vm = setup_vm(&kvm, &guest_memory, vm_resources.tee_config())?;
        (kvm, vm)
    };

    #[cfg(feature = "tee")]
    let tee = vm_resources.tee_config().tee;

    #[cfg(feature = "tee")]
    let snp_launcher = match tee {
        Tee::Snp => Some(
            vm.snp_secure_virt_prepare(&guest_memory)
                .map_err(StartMicrovmError::SecureVirtPrepare)?,
        ),
        _ => None,
    };

    #[cfg(feature = "tee")]
    let measured_regions = {
        println!("Injecting and measuring memory regions. This may take a while.");

        let qboot_size = if let Some(qboot_bundle) = &vm_resources.qboot_bundle {
            qboot_bundle.size
        } else {
            return Err(StartMicrovmError::MissingKernelConfig);
        };
        let (kernel_guest_addr, kernel_size) =
            if let Some(kernel_bundle) = &vm_resources.kernel_bundle {
                (kernel_bundle.guest_addr, kernel_bundle.size)
            } else {
                return Err(StartMicrovmError::MissingKernelConfig);
            };
        let (initrd_addr, initrd_size) = if let Some(initrd_config) = &payload_config.initrd_config
        {
            (initrd_config.address, initrd_config.size)
        } else {
            return Err(StartMicrovmError::MissingKernelConfig);
        };

        vec![
            MeasuredRegion {
                guest_addr: arch::BIOS_START,
                host_addr: guest_memory
                    .get_host_address(GuestAddress(arch::BIOS_START))
                    .unwrap() as u64,
                size: qboot_size,
            },
            MeasuredRegion {
                guest_addr: kernel_guest_addr,
                host_addr: guest_memory
                    .get_host_address(GuestAddress(kernel_guest_addr))
                    .unwrap() as u64,
                size: kernel_size,
            },
            MeasuredRegion {
                guest_addr: initrd_addr.0,
                host_addr: guest_memory.get_host_address(initrd_addr).unwrap() as u64,
                size: initrd_size,
            },
            MeasuredRegion {
                guest_addr: arch::x86_64::layout::ZERO_PAGE_START,
                host_addr: guest_memory
                    .get_host_address(GuestAddress(arch::x86_64::layout::ZERO_PAGE_START))
                    .unwrap() as u64,
                size: 4096,
            },
        ]
    };

    // On x86_64 always create a serial device,
    // while on aarch64 only create it if 'console=' is specified in the boot args.
    let serial_device = if cfg!(feature = "efi") {
        Some(setup_serial_device(
            event_manager,
            None,
            None,
            // Uncomment this to get EFI output when debugging EDK2.
            //Some(Box::new(io::stdout())),
        )?)
    } else {
        None
    };

    let exit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK)
        .map_err(Error::EventFd)
        .map_err(StartMicrovmError::Internal)?;

    #[cfg(target_arch = "x86_64")]
    // Safe to unwrap 'serial_device' as it's always 'Some' on x86_64.
    // x86_64 uses the i8042 reset event as the Vmm exit event.
    let mut pio_device_manager = PortIODeviceManager::new(
        serial_device,
        exit_evt
            .try_clone()
            .map_err(Error::EventFd)
            .map_err(StartMicrovmError::Internal)?,
    )
    .map_err(Error::CreateLegacyDevice)
    .map_err(StartMicrovmError::Internal)?;

    // Instantiate the MMIO device manager.
    // 'mmio_base' address has to be an address which is protected by the kernel
    // and is architectural specific.
    #[allow(unused_mut)]
    let mut mmio_device_manager = MMIODeviceManager::new(
        &mut (arch::MMIO_MEM_START.clone()),
        (arch::IRQ_BASE, arch::IRQ_MAX),
    );

    #[cfg(target_os = "macos")]
    let vcpu_list = {
        let cpu_count = vm_resources.vm_config().vcpu_count.unwrap();
        Arc::new(VcpuList::new(cpu_count as u64))
    };

    let vcpus;
    let intc: IrqChip;
    // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
    // while on aarch64 we need to do it the other way around.
    #[cfg(target_arch = "x86_64")]
    {
        let ioapic: Box<dyn IrqChipT> = if vm_resources.split_irqchip {
            Box::new(
                IoApic::new(vm.fd(), _sender.clone())
                    .map_err(StartMicrovmError::CreateKvmIrqChip)?,
            )
        } else {
            Box::new(KvmIoapic::new(vm.fd()).map_err(StartMicrovmError::CreateKvmIrqChip)?)
        };
        intc = Arc::new(Mutex::new(IrqChipDevice::new(ioapic)));

        attach_legacy_devices(
            &vm,
            vm_resources.split_irqchip,
            &mut pio_device_manager,
            &mut mmio_device_manager,
            Some(intc.clone()),
        )?;

        vcpus = create_vcpus_x86_64(
            &vm,
            &vcpu_config,
            &guest_memory,
            payload_config.entry_addr,
            &pio_device_manager.io_bus,
            &exit_evt,
            #[cfg(feature = "tee")]
            _sender,
        )
        .map_err(StartMicrovmError::Internal)?;
    }

    // On aarch64, the vCPUs need to be created (i.e call KVM_CREATE_VCPU) and configured before
    // setting up the IRQ chip because the `KVM_CREATE_VCPU` ioctl will return error if the IRQCHIP
    // was already initialized.
    // Search for `kvm_arch_vcpu_create` in arch/arm/kvm/arm.c.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        vcpus = create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &guest_memory,
            payload_config.entry_addr,
            &exit_evt,
        )
        .map_err(StartMicrovmError::Internal)?;

        intc = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmGicV3::new(
            vm.fd(),
            vm_resources.vm_config().vcpu_count.unwrap() as u64,
        )))));

        attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            serial_device,
        )?;
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        intc = {
            // If the system supports the in-kernel GIC, use it. Otherwise, fall back to the
            // userspace implementation.
            let gic = match HvfGicV3::new(vm_resources.vm_config().vcpu_count.unwrap() as u64) {
                Ok(hvfgic) => IrqChipDevice::new(Box::new(hvfgic)),
                Err(_) => IrqChipDevice::new(Box::new(GicV3::new(vcpu_list.clone()))),
            };
            Arc::new(Mutex::new(gic))
        };

        vcpus = create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &guest_memory,
            payload_config.entry_addr,
            &exit_evt,
            vcpu_list.clone(),
            vm_resources.nested_enabled,
        )
        .map_err(StartMicrovmError::Internal)?;

        attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_device,
            event_manager,
            _shutdown_efd,
        )?;
    }

    // We use this atomic to record the exit code set by init/init.c in the VM.
    let exit_code = Arc::new(AtomicI32::new(i32::MAX));

    let mut vmm = Vmm {
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

    #[cfg(not(feature = "tee"))]
    attach_balloon_device(&mut vmm, event_manager, intc.clone())?;
    #[cfg(not(feature = "tee"))]
    attach_rng_device(&mut vmm, event_manager, intc.clone())?;
    attach_console_devices(
        &mut vmm,
        event_manager,
        intc.clone(),
        vm_resources.console_output.clone(),
    )?;

    #[cfg(not(feature = "tee"))]
    let export_table: Option<ExportTable> = if cfg!(feature = "gpu") {
        Some(Default::default())
    } else {
        None
    };

    #[cfg(feature = "gpu")]
    if let Some(virgl_flags) = vm_resources.gpu_virgl_flags {
        attach_gpu_device(
            &mut vmm,
            event_manager,
            &mut _shm_manager,
            #[cfg(not(feature = "tee"))]
            export_table.clone(),
            intc.clone(),
            virgl_flags,
            #[cfg(target_os = "macos")]
            _sender.clone(),
        )?;
    }

    #[cfg(not(feature = "tee"))]
    attach_fs_devices(
        &mut vmm,
        &vm_resources.fs,
        &mut _shm_manager,
        #[cfg(not(feature = "tee"))]
        export_table,
        intc.clone(),
        exit_code,
        #[cfg(target_os = "macos")]
        _sender,
    )?;
    #[cfg(feature = "blk")]
    attach_block_devices(&mut vmm, &vm_resources.block, intc.clone())?;
    if let Some(vsock) = vm_resources.vsock.get() {
        attach_unixsock_vsock_device(&mut vmm, vsock, event_manager, intc.clone())?;
        #[cfg(not(feature = "net"))]
        vmm.kernel_cmdline.insert_str("tsi_hijack")?;
        #[cfg(feature = "net")]
        if vm_resources
            .net_builder
            .iter()
            .collect::<Vec<_>>()
            .is_empty()
        {
            // Only enable TSI if we don't have any network devices.
            vmm.kernel_cmdline.insert_str("tsi_hijack")?;
        }
    }
    #[cfg(feature = "net")]
    attach_net_devices(&mut vmm, vm_resources.net_builder.iter(), intc.clone())?;
    #[cfg(feature = "snd")]
    if vm_resources.snd_device {
        attach_snd_device(&mut vmm, intc.clone())?;
    }

    if let Some(s) = &vm_resources.boot_config.kernel_cmdline_epilog {
        vmm.kernel_cmdline.insert_str(s).unwrap();
    };

    // Write the kernel command line to guest memory. This is x86_64 specific, since on
    // aarch64 the command line will be specified through the FDT.
    #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
    load_cmdline(&vmm)?;

    vmm.configure_system(
        vcpus.as_slice(),
        &intc,
        &payload_config.initrd_config,
        &vm_resources.smbios_oem_strings,
    )
    .map_err(StartMicrovmError::Internal)?;

    #[cfg(feature = "tee")]
    {
        match tee {
            Tee::Snp => {
                let cpuid = kvm
                    .fd()
                    .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
                    .map_err(VstateError::KvmCpuId)
                    .map_err(StartMicrovmError::SecureVirtAttest)?;
                vmm.kvm_vm()
                    .snp_secure_virt_measure(
                        cpuid,
                        vmm.guest_memory(),
                        measured_regions,
                        snp_launcher.unwrap(),
                    )
                    .map_err(StartMicrovmError::SecureVirtAttest)?;
            }
            _ => return Err(StartMicrovmError::InvalidTee),
        }

        println!("Starting TEE/microVM.");
    }

    vmm.start_vcpus(vcpus)
        .map_err(StartMicrovmError::Internal)?;

    // Clippy thinks we don't need Arc<Mutex<...
    // but we don't want to change the event_manager interface
    #[allow(clippy::arc_with_non_send_sync)]
    let vmm = Arc::new(Mutex::new(vmm));
    event_manager
        .add_subscriber(vmm.clone())
        .map_err(StartMicrovmError::RegisterEvent)?;

    Ok(vmm)
}

fn load_external_kernel(
    guest_mem: &GuestMemoryMmap,
    arch_mem_info: &ArchMemoryInfo,
    external_kernel: &ExternalKernel,
) -> std::result::Result<(GuestAddress, Option<InitrdConfig>, Option<String>), StartMicrovmError> {
    let entry_addr = match external_kernel.format {
        // Raw images are treated as bundled kernels on x86_64
        #[cfg(target_arch = "x86_64")]
        KernelFormat::Raw => unreachable!(),
        #[cfg(target_arch = "aarch64")]
        KernelFormat::Raw => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::RawOpenKernel)?;
            guest_mem.write(&data, GuestAddress(0x8000_0000)).unwrap();
            GuestAddress(0x8000_0000)
        }
        #[cfg(target_arch = "x86_64")]
        KernelFormat::Elf => {
            let mut file = File::options()
                .read(true)
                .write(false)
                .open(external_kernel.path.clone())
                .map_err(StartMicrovmError::ElfOpenKernel)?;
            let load_result = loader::Elf::load(guest_mem, None, &mut file, None)
                .map_err(StartMicrovmError::ElfLoadKernel)?;
            load_result.kernel_load
        }
        #[cfg(target_arch = "aarch64")]
        KernelFormat::PeGz => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::PeGzOpenKernel)?;
            if let Some(magic) = data
                .windows(3)
                .position(|window| window == [0x1f, 0x8b, 0x8])
            {
                debug!("Found GZIP header on PE file at: 0x{:x}", magic);
                let (_, compressed) = data.split_at(magic);
                let mut gz = GzDecoder::new(compressed);
                let mut kernel_data: Vec<u8> = Vec::new();
                gz.read_to_end(&mut kernel_data)
                    .map_err(StartMicrovmError::PeGzDecoder)?;
                guest_mem
                    .write(&kernel_data, GuestAddress(0x8000_0000))
                    .unwrap();
                GuestAddress(0x8000_0000)
            } else {
                return Err(StartMicrovmError::PeGzInvalid);
            }
        }
        #[cfg(target_arch = "x86_64")]
        KernelFormat::ImageBz2 => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::ImageBz2OpenKernel)?;
            if let Some(magic) = data
                .windows(4)
                .position(|window| window == [b'B', b'Z', b'h'])
            {
                debug!("Found BZIP2 header on Image file at: 0x{:x}", magic);
                let (_, compressed) = data.split_at(magic);
                let mut kernel_data: Vec<u8> = Vec::new();
                let mut bz2 = bzip2::read::BzDecoder::new(compressed);
                bz2.read_to_end(&mut kernel_data)
                    .map_err(StartMicrovmError::ImageBz2Decoder)?;
                let load_result = loader::Elf::load(
                    guest_mem,
                    None,
                    &mut std::io::Cursor::new(kernel_data),
                    None,
                )
                .map_err(StartMicrovmError::ImageBz2LoadKernel)?;
                load_result.kernel_load
            } else {
                return Err(StartMicrovmError::ImageBz2Invalid);
            }
        }
        #[cfg(target_arch = "x86_64")]
        KernelFormat::ImageGz => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::ImageGzOpenKernel)?;
            if let Some(magic) = data
                .windows(3)
                .position(|window| window == [0x1f, 0x8b, 0x8])
            {
                debug!("Found GZIP header on Image file at: 0x{:x}", magic);
                let (_, compressed) = data.split_at(magic);
                let mut gz = GzDecoder::new(compressed);
                let mut kernel_data: Vec<u8> = Vec::new();
                gz.read_to_end(&mut kernel_data)
                    .map_err(StartMicrovmError::ImageGzDecoder)?;
                let load_result = loader::Elf::load(
                    guest_mem,
                    None,
                    &mut std::io::Cursor::new(kernel_data),
                    None,
                )
                .map_err(StartMicrovmError::ImageGzLoadKernel)?;
                load_result.kernel_load
            } else {
                return Err(StartMicrovmError::ImageGzInvalid);
            }
        }
        #[cfg(target_arch = "x86_64")]
        KernelFormat::ImageZstd => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::ImageZstdOpenKernel)?;
            if let Some(magic) = data
                .windows(4)
                .position(|window| window == [0x28, 0xb5, 0x2f, 0xfd])
            {
                debug!("Found ZSTD header on Image file at: 0x{:x}", magic);
                let (_, zstd_data) = data.split_at(magic);
                let mut kernel_data: Vec<u8> = Vec::new();
                let _ = zstd::stream::copy_decode(zstd_data, &mut kernel_data);
                let load_result = loader::Elf::load(
                    guest_mem,
                    None,
                    &mut std::io::Cursor::new(kernel_data),
                    None,
                )
                .map_err(StartMicrovmError::ImageZstdLoadKernel)?;
                load_result.kernel_load
            } else {
                return Err(StartMicrovmError::ImageZstdInvalid);
            }
        }
        _ => return Err(StartMicrovmError::KernelFormatUnsupported),
    };

    debug!("load_external_kernel: 0x{:x}", entry_addr.0);

    let initrd_config = if let Some(initramfs_path) = &external_kernel.initramfs_path {
        let data = std::fs::read(initramfs_path).map_err(StartMicrovmError::InitrdRead)?;
        guest_mem
            .write(&data, GuestAddress(arch_mem_info.initrd_addr))
            .unwrap();
        Some(InitrdConfig {
            address: GuestAddress(arch_mem_info.initrd_addr),
            size: data.len(),
        })
    } else {
        None
    };

    Ok((entry_addr, initrd_config, external_kernel.cmdline.clone()))
}

fn load_payload(
    _vm_resources: &VmResources,
    guest_mem: GuestMemoryMmap,
    _arch_mem_info: &ArchMemoryInfo,
    payload: &Payload,
) -> std::result::Result<
    (
        GuestMemoryMmap,
        GuestAddress,
        Option<InitrdConfig>,
        Option<String>,
    ),
    StartMicrovmError,
> {
    match payload {
        #[cfg(target_arch = "aarch64")]
        Payload::KernelCopy => {
            let (kernel_entry_addr, kernel_host_addr, kernel_guest_addr, kernel_size) =
                if let Some(kernel_bundle) = &_vm_resources.kernel_bundle {
                    (
                        kernel_bundle.entry_addr,
                        kernel_bundle.host_addr,
                        kernel_bundle.guest_addr,
                        kernel_bundle.size,
                    )
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };

            let kernel_data =
                unsafe { std::slice::from_raw_parts(kernel_host_addr as *mut u8, kernel_size) };
            guest_mem
                .write(kernel_data, GuestAddress(kernel_guest_addr))
                .unwrap();
            Ok((guest_mem, GuestAddress(kernel_entry_addr), None, None))
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
        Payload::KernelMmap => {
            let (kernel_entry_addr, kernel_host_addr, kernel_guest_addr, kernel_size) =
                if let Some(kernel_bundle) = &_vm_resources.kernel_bundle {
                    (
                        kernel_bundle.entry_addr,
                        kernel_bundle.host_addr,
                        kernel_bundle.guest_addr,
                        kernel_bundle.size,
                    )
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };

            let kernel_region = unsafe {
                MmapRegion::build_raw(kernel_host_addr as *mut u8, kernel_size, 0, 0)
                    .map_err(StartMicrovmError::InvalidKernelBundle)?
            };

            Ok((
                guest_mem
                    .insert_region(Arc::new(
                        GuestRegionMmap::new(kernel_region, GuestAddress(kernel_guest_addr))
                            .map_err(StartMicrovmError::GuestMemoryMmap)?,
                    ))
                    .map_err(StartMicrovmError::GuestMemoryMmap)?,
                GuestAddress(kernel_entry_addr),
                None,
                None,
            ))
        }
        Payload::ExternalKernel(external_kernel) => {
            let (entry_addr, initrd_config, cmdline) =
                load_external_kernel(&guest_mem, _arch_mem_info, external_kernel)?;
            Ok((guest_mem, entry_addr, initrd_config, cmdline))
        }
        #[cfg(test)]
        Payload::Empty => Ok((guest_mem, GuestAddress(0), None, None)),
        #[cfg(feature = "tee")]
        Payload::Tee => {
            let (kernel_host_addr, kernel_guest_addr, kernel_size) =
                if let Some(kernel_bundle) = &_vm_resources.kernel_bundle {
                    (
                        kernel_bundle.host_addr,
                        kernel_bundle.guest_addr,
                        kernel_bundle.size,
                    )
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };
            let kernel_data =
                unsafe { std::slice::from_raw_parts(kernel_host_addr as *mut u8, kernel_size) };
            guest_mem
                .write(kernel_data, GuestAddress(kernel_guest_addr))
                .unwrap();

            let (qboot_host_addr, qboot_size) =
                if let Some(qboot_bundle) = &_vm_resources.qboot_bundle {
                    (qboot_bundle.host_addr, qboot_bundle.size)
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };
            let qboot_data =
                unsafe { std::slice::from_raw_parts(qboot_host_addr as *mut u8, qboot_size) };
            guest_mem
                .write(qboot_data, GuestAddress(arch::BIOS_START))
                .unwrap();

            let (initrd_host_addr, initrd_size) =
                if let Some(initrd_bundle) = &_vm_resources.initrd_bundle {
                    (initrd_bundle.host_addr, initrd_bundle.size)
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };
            let initrd_data =
                unsafe { std::slice::from_raw_parts(initrd_host_addr as *mut u8, initrd_size) };
            guest_mem
                .write(initrd_data, GuestAddress(_arch_mem_info.initrd_addr))
                .unwrap();

            let initrd_config = InitrdConfig {
                address: GuestAddress(_arch_mem_info.initrd_addr),
                size: initrd_data.len(),
            };

            Ok((
                guest_mem,
                GuestAddress(arch::RESET_VECTOR),
                Some(initrd_config),
                None,
            ))
        }
        #[cfg(feature = "efi")]
        Payload::Efi => {
            guest_mem.write(EDK2_BINARY, GuestAddress(0u64)).unwrap();
            Ok((guest_mem, GuestAddress(0), None, None))
        }
        #[cfg(not(feature = "efi"))]
        Payload::Efi => {
            unreachable!("EFI support was not built in")
        }
    }
}

struct PayloadConfig {
    entry_addr: GuestAddress,
    initrd_config: Option<InitrdConfig>,
    kernel_cmdline: Option<String>,
}

fn create_guest_memory(
    mem_size: usize,
    vm_resources: &VmResources,
    payload: &Payload,
) -> std::result::Result<
    (GuestMemoryMmap, ArchMemoryInfo, ShmManager, PayloadConfig),
    StartMicrovmError,
> {
    let mem_size = mem_size << 20;

    #[cfg(target_arch = "x86_64")]
    let (arch_mem_info, mut arch_mem_regions) = match payload {
        #[cfg(not(feature = "tee"))]
        Payload::KernelMmap => {
            let (kernel_guest_addr, kernel_size) =
                if let Some(kernel_bundle) = &vm_resources.kernel_bundle {
                    (kernel_bundle.guest_addr, kernel_bundle.size)
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };
            arch::arch_memory_regions(mem_size, Some(kernel_guest_addr), kernel_size, 0)
        }
        Payload::ExternalKernel(external_kernel) => {
            arch::arch_memory_regions(mem_size, None, 0, external_kernel.initramfs_size)
        }
        #[cfg(feature = "tee")]
        Payload::Tee => {
            let (kernel_guest_addr, kernel_size) =
                if let Some(kernel_bundle) = &vm_resources.kernel_bundle {
                    (kernel_bundle.guest_addr, kernel_bundle.size)
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };
            arch::arch_memory_regions(mem_size, Some(kernel_guest_addr), kernel_size, 0)
        }
        #[cfg(test)]
        Payload::Empty => arch::arch_memory_regions(mem_size, None, 0, 0),
        Payload::Efi => unreachable!(),
    };
    #[cfg(target_arch = "aarch64")]
    let (arch_mem_info, mut arch_mem_regions) = match payload {
        Payload::ExternalKernel(external_kernel) => {
            arch::arch_memory_regions(mem_size, external_kernel.initramfs_size)
        }
        _ => arch::arch_memory_regions(mem_size, 0),
    };

    let mut shm_manager = ShmManager::new(&arch_mem_info);

    #[cfg(not(feature = "tee"))]
    for (index, fs) in vm_resources.fs.iter().enumerate() {
        if let Some(shm_size) = fs.shm_size {
            shm_manager
                .create_fs_region(index, shm_size)
                .map_err(StartMicrovmError::ShmCreate)?;
        }
    }
    if vm_resources.gpu_virgl_flags.is_some() {
        let size = vm_resources.gpu_shm_size.unwrap_or(1 << 33);
        shm_manager
            .create_gpu_region(size)
            .map_err(StartMicrovmError::ShmCreate)?;
    }

    arch_mem_regions.extend(shm_manager.regions());

    let guest_mem = GuestMemoryMmap::from_ranges(&arch_mem_regions)
        .map_err(StartMicrovmError::GuestMemoryMmap)?;

    let (guest_mem, entry_addr, initrd_config, cmdline) =
        load_payload(vm_resources, guest_mem, &arch_mem_info, payload)?;

    let payload_config = PayloadConfig {
        entry_addr,
        initrd_config,
        kernel_cmdline: cmdline.clone(),
    };

    Ok((guest_mem, arch_mem_info, shm_manager, payload_config))
}

#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
fn load_cmdline(vmm: &Vmm) -> std::result::Result<(), StartMicrovmError> {
    kernel::loader::load_cmdline(
        vmm.guest_memory(),
        GuestAddress(arch::x86_64::layout::CMDLINE_START),
        &vmm.kernel_cmdline
            .as_cstring()
            .map_err(StartMicrovmError::LoadCommandline)?,
    )
    .map_err(StartMicrovmError::LoadCommandline)
}

#[cfg(all(target_os = "linux", not(feature = "tee")))]
pub(crate) fn setup_vm(
    guest_memory: &GuestMemoryMmap,
    _nested_enabled: bool,
) -> std::result::Result<Vm, StartMicrovmError> {
    let kvm = KvmContext::new()
        .map_err(Error::KvmContext)
        .map_err(StartMicrovmError::Internal)?;
    let mut vm = Vm::new(kvm.fd())
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    vm.memory_init(guest_memory, kvm.max_memslots())
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    Ok(vm)
}
#[cfg(all(target_os = "linux", feature = "tee"))]
pub(crate) fn setup_vm(
    kvm: &KvmContext,
    guest_memory: &GuestMemoryMmap,
    tee_config: &TeeConfig,
) -> std::result::Result<Vm, StartMicrovmError> {
    let mut vm = Vm::new(kvm.fd(), tee_config)
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    vm.memory_init(guest_memory, kvm.max_memslots())
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    Ok(vm)
}
#[cfg(target_os = "macos")]
pub(crate) fn setup_vm(
    guest_memory: &GuestMemoryMmap,
    nested_enabled: bool,
) -> std::result::Result<Vm, StartMicrovmError> {
    let mut vm = Vm::new(nested_enabled)
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    vm.memory_init(guest_memory)
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    Ok(vm)
}

/// Sets up the serial device.
pub fn setup_serial_device(
    event_manager: &mut EventManager,
    input: Option<Box<dyn devices::legacy::ReadableFd + Send>>,
    out: Option<Box<dyn io::Write + Send>>,
) -> std::result::Result<Arc<Mutex<Serial>>, StartMicrovmError> {
    let interrupt_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK)
        .map_err(Error::EventFd)
        .map_err(StartMicrovmError::Internal)?;
    let has_input = input.is_some();
    let serial = Arc::new(Mutex::new(Serial::new(interrupt_evt, out, input)));
    if has_input {
        if let Err(e) = event_manager.add_subscriber(serial.clone()) {
            // TODO: We just log this message, and immediately return Ok, instead of returning the
            // actual error because this operation always fails with EPERM when adding a fd which
            // has been redirected to /dev/null via dup2 (this may happen inside the jailer).
            // Find a better solution to this (and think about the state of the serial device
            // while we're at it).
            warn!("Could not add serial input event to epoll: {:?}", e);
        }
    }
    Ok(serial)
}

#[cfg(target_arch = "x86_64")]
fn attach_legacy_devices(
    vm: &Vm,
    split_irqchip: bool,
    pio_device_manager: &mut PortIODeviceManager,
    mmio_device_manager: &mut MMIODeviceManager,
    intc: Option<Arc<Mutex<IrqChipDevice>>>,
) -> std::result::Result<(), StartMicrovmError> {
    pio_device_manager
        .register_devices()
        .map_err(Error::LegacyIOBus)
        .map_err(StartMicrovmError::Internal)?;

    if split_irqchip {
        mmio_device_manager
            .register_mmio_ioapic(intc)
            .map_err(Error::RegisterMMIODevice)
            .map_err(StartMicrovmError::Internal)?;
    }

    macro_rules! register_irqfd_evt {
        ($evt: ident, $index: expr) => {{
            vm.fd()
                .register_irqfd(&pio_device_manager.$evt, $index)
                .map_err(|e| {
                    Error::LegacyIOBus(device_manager::legacy::Error::EventFd(
                        io::Error::from_raw_os_error(e.errno()),
                    ))
                })
                .map_err(StartMicrovmError::Internal)?;
        }};
    }

    register_irqfd_evt!(com_evt_1_3, 4);
    register_irqfd_evt!(com_evt_2_4, 3);
    register_irqfd_evt!(kbd_evt, 1);
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn attach_legacy_devices(
    vm: &Vm,
    mmio_device_manager: &mut MMIODeviceManager,
    kernel_cmdline: &mut kernel::cmdline::Cmdline,
    serial: Option<Arc<Mutex<Serial>>>,
) -> std::result::Result<(), StartMicrovmError> {
    if let Some(serial) = serial {
        mmio_device_manager
            .register_mmio_serial(vm.fd(), kernel_cmdline, serial)
            .map_err(Error::RegisterMMIODevice)
            .map_err(StartMicrovmError::Internal)?;
    }

    mmio_device_manager
        .register_mmio_rtc(vm.fd())
        .map_err(Error::RegisterMMIODevice)
        .map_err(StartMicrovmError::Internal)?;

    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
fn attach_legacy_devices(
    vm: &Vm,
    mmio_device_manager: &mut MMIODeviceManager,
    kernel_cmdline: &mut kernel::cmdline::Cmdline,
    intc: IrqChip,
    serial: Option<Arc<Mutex<Serial>>>,
    event_manager: &mut EventManager,
    shutdown_efd: Option<EventFd>,
) -> Result<(), StartMicrovmError> {
    if let Some(serial) = serial {
        mmio_device_manager
            .register_mmio_serial(vm, kernel_cmdline, intc.clone(), serial)
            .map_err(Error::RegisterMMIODevice)
            .map_err(StartMicrovmError::Internal)?;
    }

    mmio_device_manager
        .register_mmio_rtc(vm, intc.clone())
        .map_err(Error::RegisterMMIODevice)
        .map_err(StartMicrovmError::Internal)?;

    mmio_device_manager
        .register_mmio_gic(vm, intc.clone())
        .map_err(Error::RegisterMMIODevice)
        .map_err(StartMicrovmError::Internal)?;

    if let Some(shutdown_efd) = shutdown_efd {
        mmio_device_manager
            .register_mmio_gpio(vm, intc.clone(), event_manager, shutdown_efd)
            .map_err(Error::RegisterMMIODevice)
            .map_err(StartMicrovmError::Internal)?;
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn create_vcpus_x86_64(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    guest_mem: &GuestMemoryMmap,
    entry_addr: GuestAddress,
    io_bus: &devices::Bus,
    exit_evt: &EventFd,
    #[cfg(feature = "tee")] pm_sender: Sender<WorkerMessage>,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    for cpu_index in 0..vcpu_config.vcpu_count {
        let mut vcpu = Vcpu::new_x86_64(
            cpu_index,
            vm.fd(),
            vm.supported_cpuid().clone(),
            vm.supported_msrs().clone(),
            io_bus.clone(),
            exit_evt.try_clone().map_err(Error::EventFd)?,
            #[cfg(feature = "tee")]
            pm_sender.clone(),
        )
        .map_err(Error::Vcpu)?;

        vcpu.configure_x86_64(guest_mem, entry_addr, vcpu_config)
            .map_err(Error::Vcpu)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn create_vcpus_aarch64(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    guest_mem: &GuestMemoryMmap,
    entry_addr: GuestAddress,
    exit_evt: &EventFd,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    for cpu_index in 0..vcpu_config.vcpu_count {
        let mut vcpu = Vcpu::new_aarch64(
            cpu_index,
            vm.fd(),
            exit_evt.try_clone().map_err(Error::EventFd)?,
        )
        .map_err(Error::Vcpu)?;

        vcpu.configure_aarch64(vm.fd(), guest_mem, entry_addr)
            .map_err(Error::Vcpu)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
fn create_vcpus_aarch64(
    _vm: &Vm,
    vcpu_config: &VcpuConfig,
    guest_mem: &GuestMemoryMmap,
    entry_addr: GuestAddress,
    exit_evt: &EventFd,
    vcpu_list: Arc<VcpuList>,
    nested_enabled: bool,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    let mut boot_senders: HashMap<u64, Sender<u64>> = HashMap::new();

    for cpu_index in 0..vcpu_config.vcpu_count {
        let (boot_sender, boot_receiver) = if cpu_index != 0 {
            let (boot_sender, boot_receiver) = unbounded();
            (Some(boot_sender), Some(boot_receiver))
        } else {
            (None, None)
        };

        let mut vcpu = Vcpu::new_aarch64(
            cpu_index,
            entry_addr,
            boot_receiver,
            exit_evt.try_clone().map_err(Error::EventFd)?,
            vcpu_list.clone(),
            nested_enabled,
        )
        .map_err(Error::Vcpu)?;

        vcpu.configure_aarch64(guest_mem).map_err(Error::Vcpu)?;

        if let Some(boot_sender) = boot_sender {
            boot_senders.insert(vcpu.get_mpidr(), boot_sender);
        }

        vcpus.push(vcpu);
    }

    vcpus[0].set_boot_senders(boot_senders);

    Ok(vcpus)
}

/// Attaches an MmioTransport device to the device manager.
fn attach_mmio_device(
    vmm: &mut Vmm,
    id: String,
    device: MmioTransport,
) -> std::result::Result<(), device_manager::mmio::Error> {
    let type_id = device
        .device()
        .lock()
        .expect("Poisoned device lock")
        .device_type();
    let _cmdline = &mut vmm.kernel_cmdline;

    #[cfg(target_os = "linux")]
    let (_mmio_base, _irq) =
        vmm.mmio_device_manager
            .register_mmio_device(vmm.vm.fd(), device, type_id, id)?;
    #[cfg(target_os = "macos")]
    let (_mmio_base, _irq) = vmm
        .mmio_device_manager
        .register_mmio_device(device, type_id, id)?;

    #[cfg(target_arch = "x86_64")]
    vmm.mmio_device_manager
        .add_device_to_cmdline(_cmdline, _mmio_base, _irq)?;

    Ok(())
}

#[cfg(not(feature = "tee"))]
fn attach_fs_devices(
    vmm: &mut Vmm,
    fs_devs: &[FsDeviceConfig],
    shm_manager: &mut ShmManager,
    #[cfg(not(feature = "tee"))] export_table: Option<ExportTable>,
    intc: IrqChip,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    for (i, config) in fs_devs.iter().enumerate() {
        let fs = Arc::new(Mutex::new(
            devices::virtio::Fs::new(
                config.fs_id.clone(),
                config.shared_dir.clone(),
                exit_code.clone(),
            )
            .unwrap(),
        ));

        let id = format!("{}{}", String::from(fs.lock().unwrap().id()), i);

        fs.lock().unwrap().set_intc(intc.clone());

        if let Some(shm_region) = shm_manager.fs_region(i) {
            fs.lock().unwrap().set_shm_region(VirtioShmRegion {
                host_addr: vmm
                    .guest_memory
                    .get_host_address(shm_region.guest_addr)
                    .map_err(StartMicrovmError::ShmHostAddr)? as u64,
                guest_addr: shm_region.guest_addr.raw_value(),
                size: shm_region.size,
            });
        }

        #[cfg(not(feature = "tee"))]
        if let Some(export_table) = export_table.as_ref() {
            fs.lock().unwrap().set_export_table(export_table.clone());
        }

        #[cfg(target_os = "macos")]
        fs.lock().unwrap().set_map_sender(map_sender.clone());

        // The device mutex mustn't be locked here otherwise it will deadlock.
        attach_mmio_device(
            vmm,
            id,
            MmioTransport::new(vmm.guest_memory().clone(), fs.clone()),
        )
        .map_err(RegisterFsDevice)?;
    }

    Ok(())
}

fn attach_console_devices(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
    console_output: Option<PathBuf>,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let ports = if let Some(console_output) = console_output {
        let file = File::create(console_output.as_path()).map_err(OpenConsoleFile)?;
        vec![PortDescription::Console {
            input: Some(port_io::input_empty().unwrap()),
            output: Some(port_io::output_file(file).unwrap()),
        }]
    } else {
        let stdin_is_terminal = isatty(STDIN_FILENO).unwrap_or(false);
        let stdout_is_terminal = isatty(STDOUT_FILENO).unwrap_or(false);
        let stderr_is_terminal = isatty(STDERR_FILENO).unwrap_or(false);

        if let Err(e) = term_set_raw_mode(!stdin_is_terminal) {
            log::error!("Failed to set terminal to raw mode: {e}")
        }

        let console_input = if stdin_is_terminal {
            Some(port_io::stdin().unwrap())
        } else {
            #[cfg(target_os = "linux")]
            {
                let sigint_input = port_io::PortInputSigInt::new();
                let sigint_input_fd = sigint_input.sigint_evt().as_raw_fd();
                register_sigint_handler(sigint_input_fd).map_err(RegisterFsSigwinch)?;
                Some(Box::new(sigint_input) as _)
            }
            #[cfg(not(target_os = "linux"))]
            Some(port_io::input_empty().unwrap())
        };

        let console_output = if stdout_is_terminal {
            Some(port_io::stdout().unwrap())
        } else {
            Some(port_io::output_to_log_as_err())
        };

        let mut ports = vec![PortDescription::Console {
            input: console_input,
            output: console_output,
        }];

        if !stdin_is_terminal {
            ports.push(PortDescription::InputPipe {
                name: "krun-stdin".into(),
                input: port_io::stdin().unwrap(),
            })
        }

        if !stdout_is_terminal {
            ports.push(PortDescription::OutputPipe {
                name: "krun-stdout".into(),
                output: port_io::stdout().unwrap(),
            })
        };

        if !stderr_is_terminal {
            ports.push(PortDescription::OutputPipe {
                name: "krun-stderr".into(),
                output: port_io::stderr().unwrap(),
            });
        }

        ports
    };

    let console = Arc::new(Mutex::new(devices::virtio::Console::new(ports).unwrap()));

    vmm.exit_observers.push(console.clone());

    console.lock().unwrap().set_intc(intc);

    event_manager
        .add_subscriber(console.clone())
        .map_err(RegisterEvent)?;

    #[cfg(target_os = "linux")]
    register_sigwinch_handler(console.lock().unwrap().get_sigwinch_fd())
        .map_err(RegisterFsSigwinch)?;

    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_mmio_device(
        vmm,
        "hvc0".to_string(),
        MmioTransport::new(vmm.guest_memory().clone(), console),
    )
    .map_err(RegisterFsDevice)?;

    Ok(())
}

#[cfg(feature = "net")]
fn attach_net_devices<'a>(
    vmm: &mut Vmm,
    net_devices: impl Iterator<Item = &'a Arc<Mutex<Net>>>,
    intc: IrqChip,
) -> Result<(), StartMicrovmError> {
    for net_device in net_devices {
        let id = net_device.lock().unwrap().id().to_string();

        net_device.lock().unwrap().set_intc(intc.clone());

        attach_mmio_device(
            vmm,
            id,
            MmioTransport::new(vmm.guest_memory.clone(), net_device.clone()),
        )
        .map_err(StartMicrovmError::RegisterNetDevice)?;
    }
    Ok(())
}

fn attach_unixsock_vsock_device(
    vmm: &mut Vmm,
    unix_vsock: &Arc<Mutex<Vsock>>,
    event_manager: &mut EventManager,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    event_manager
        .add_subscriber(unix_vsock.clone())
        .map_err(RegisterEvent)?;

    let id = String::from(unix_vsock.lock().unwrap().id());

    unix_vsock.lock().unwrap().set_intc(intc);

    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_mmio_device(
        vmm,
        id,
        MmioTransport::new(vmm.guest_memory().clone(), unix_vsock.clone()),
    )
    .map_err(RegisterVsockDevice)?;

    Ok(())
}

#[cfg(not(feature = "tee"))]
fn attach_balloon_device(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let balloon = Arc::new(Mutex::new(devices::virtio::Balloon::new().unwrap()));

    event_manager
        .add_subscriber(balloon.clone())
        .map_err(RegisterEvent)?;

    let id = String::from(balloon.lock().unwrap().id());

    balloon.lock().unwrap().set_intc(intc);

    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_mmio_device(
        vmm,
        id,
        MmioTransport::new(vmm.guest_memory().clone(), balloon),
    )
    .map_err(RegisterBalloonDevice)?;

    Ok(())
}

#[cfg(feature = "blk")]
fn attach_block_devices(
    vmm: &mut Vmm,
    block_devs: &BlockBuilder,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    for block in block_devs.list.iter() {
        let id = String::from(block.lock().unwrap().id());

        block.lock().unwrap().set_intc(intc.clone());

        // The device mutex mustn't be locked here otherwise it will deadlock.
        attach_mmio_device(
            vmm,
            id,
            MmioTransport::new(vmm.guest_memory().clone(), block.clone()),
        )
        .map_err(RegisterBlockDevice)?;
    }

    Ok(())
}

#[cfg(not(feature = "tee"))]
fn attach_rng_device(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let rng = Arc::new(Mutex::new(devices::virtio::Rng::new().unwrap()));

    event_manager
        .add_subscriber(rng.clone())
        .map_err(RegisterEvent)?;

    let id = String::from(rng.lock().unwrap().id());

    rng.lock().unwrap().set_intc(intc);

    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_mmio_device(vmm, id, MmioTransport::new(vmm.guest_memory().clone(), rng))
        .map_err(RegisterRngDevice)?;

    Ok(())
}

#[cfg(feature = "gpu")]
fn attach_gpu_device(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    shm_manager: &mut ShmManager,
    #[cfg(not(feature = "tee"))] mut export_table: Option<ExportTable>,
    intc: IrqChip,
    virgl_flags: u32,
    #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let gpu = Arc::new(Mutex::new(
        devices::virtio::Gpu::new(
            virgl_flags,
            #[cfg(target_os = "macos")]
            map_sender,
        )
        .unwrap(),
    ));

    event_manager
        .add_subscriber(gpu.clone())
        .map_err(RegisterEvent)?;

    let id = String::from(gpu.lock().unwrap().id());

    gpu.lock().unwrap().set_intc(intc);

    if let Some(shm_region) = shm_manager.gpu_region() {
        gpu.lock().unwrap().set_shm_region(VirtioShmRegion {
            host_addr: vmm
                .guest_memory
                .get_host_address(shm_region.guest_addr)
                .map_err(StartMicrovmError::ShmHostAddr)? as u64,
            guest_addr: shm_region.guest_addr.raw_value(),
            size: shm_region.size,
        });
    }

    #[cfg(not(feature = "tee"))]
    if let Some(export_table) = export_table.take() {
        gpu.lock().unwrap().set_export_table(export_table);
    }

    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_mmio_device(vmm, id, MmioTransport::new(vmm.guest_memory().clone(), gpu))
        .map_err(RegisterGpuDevice)?;

    Ok(())
}

#[cfg(feature = "snd")]
fn attach_snd_device(vmm: &mut Vmm, intc: IrqChip) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let snd = Arc::new(Mutex::new(devices::virtio::Snd::new().unwrap()));
    let id = String::from(snd.lock().unwrap().id());

    snd.lock().unwrap().set_intc(intc);

    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_mmio_device(vmm, id, MmioTransport::new(vmm.guest_memory().clone(), snd))
        .map_err(RegisterSndDevice)?;

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::vmm_config::kernel_bundle::KernelBundle;

    fn default_guest_memory(
        mem_size_mib: usize,
    ) -> std::result::Result<
        (GuestMemoryMmap, ArchMemoryInfo, ShmManager, PayloadConfig),
        StartMicrovmError,
    > {
        let mut vm_resources = VmResources::default();
        vm_resources.kernel_bundle = Some(KernelBundle {
            host_addr: 0x1000,
            guest_addr: 0x1000,
            entry_addr: 0x1000,
            size: 0x1000,
        });

        create_guest_memory(mem_size_mib, &vm_resources, &Payload::KernelMmap)
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_create_vcpus_x86_64() {
        let vcpu_count = 2;

        let vcpu_config = VcpuConfig {
            vcpu_count,
            ht_enabled: false,
            cpu_template: None,
        };

        let (guest_memory, _arch_memory_info, _shm_manager, _payload_config) =
            default_guest_memory(128).unwrap();
        let vm = setup_vm(&guest_memory, false).unwrap();
        let _kvmioapic = KvmIoapic::new(&vm.fd()).unwrap();

        // Dummy entry_addr, vcpus will not boot.
        let entry_addr = GuestAddress(0);
        let bus = devices::Bus::new();
        let vcpu_vec = create_vcpus_x86_64(
            &vm,
            &vcpu_config,
            &guest_memory,
            entry_addr,
            &bus,
            &EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();
        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }

    #[test]
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn test_create_vcpus_aarch64() {
        let (guest_memory, _arch_memory_info) =
            create_guest_memory(128, None, Payload::Empty).unwrap();
        let vm = setup_vm(&guest_memory, false).unwrap();
        let vcpu_count = 2;

        let vcpu_config = VcpuConfig {
            vcpu_count,
            ht_enabled: false,
            cpu_template: None,
        };

        // Dummy entry_addr, vcpus will not boot.
        let entry_addr = GuestAddress(0);
        let vcpu_vec = create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &guest_memory,
            entry_addr,
            &EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();
        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }

    #[test]
    fn test_error_messages() {
        use crate::builder::StartMicrovmError::*;
        let err = AttachBlockDevice(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = CreateRateLimiter(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = Internal(Error::Serial(io::Error::from_raw_os_error(0)));
        let _ = format!("{}{:?}", err, err);

        let err = InvalidKernelBundle(vm_memory::mmap::MmapRegionError::InvalidPointer);
        let _ = format!("{}{:?}", err, err);

        let err = KernelCmdline(String::from("dummy --cmdline"));
        let _ = format!("{}{:?}", err, err);

        let err = LoadCommandline(kernel::cmdline::Error::TooLarge);
        let _ = format!("{}{:?}", err, err);

        let err = MicroVMAlreadyRunning;
        let _ = format!("{}{:?}", err, err);

        let err = MissingKernelConfig;
        let _ = format!("{}{:?}", err, err);

        let err = MissingMemSizeConfig;
        let _ = format!("{}{:?}", err, err);

        let err = NetDeviceNotConfigured;
        let _ = format!("{}{:?}", err, err);

        let err = OpenBlockDevice(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = RegisterBlockDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{}{:?}", err, err);

        let err = RegisterEvent(EventManagerError::EpollCreate(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{}{:?}", err, err);

        let err = RegisterNetDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{}{:?}", err, err);

        let err = RegisterVsockDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{}{:?}", err, err);
    }

    #[test]
    fn test_kernel_cmdline_err_to_startuvm_err() {
        let err = StartMicrovmError::from(kernel::cmdline::Error::HasSpace);
        let _ = format!("{}{:?}", err, err);
    }
}

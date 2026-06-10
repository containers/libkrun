// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enables pre-boot setup, instantiation and booting of a Firecracker VMM.

// v1 device-attach helpers are kept for reference but currently unused (v2 API
// attaches devices directly).  Suppress warnings until they are either ported
// to the v2 API or removed.
#![allow(dead_code, unused_imports)]

use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};

use super::{Error, Vmm};

#[cfg(target_arch = "x86_64")]
use crate::device_manager::legacy::PortIODeviceManager;
use crate::device_manager::mmio::MMIODeviceManager;
use crate::resources::{
    DefaultVirtioConsoleConfig, PortConfig, VirtioConsoleConfigMode, VmResources,
};
use crate::vmm_config::external_kernel::{ExternalKernel, KernelFormat};
#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
use devices::legacy::KvmAia;
use devices::legacy::Serial;
#[cfg(target_os = "macos")]
use devices::legacy::VcpuList;
#[cfg(target_os = "macos")]
use devices::legacy::{GicV3, HvfGicV3};
use devices::legacy::{IrqChip, IrqChipDevice};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use devices::legacy::{KvmGicV2, KvmGicV3};
use devices::virtio::{MmioTransport, PortDescription, VirtioDevice, Vsock, port_io};

#[cfg(feature = "tee")]
use kbs_types::Tee;

use crate::device_manager;
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
use crate::resources::VhostUserDeviceConfig;
#[cfg(target_os = "linux")]
use crate::signal_handler::register_sigint_handler;
#[cfg(target_os = "linux")]
use crate::signal_handler::register_sigwinch_handler;
use crate::terminal::{term_restore_mode, term_set_raw_mode};
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use crate::vmm_config::fs::FsDeviceConfig;
#[cfg(target_os = "linux")]
use crate::vstate::KvmContext;
#[cfg(all(target_os = "linux", feature = "tee"))]
use crate::vstate::MeasuredRegion;
use crate::vstate::{Error as VstateError, Vcpu, VcpuConfig, Vm};
use arch::{ArchMemoryInfo, InitrdConfig};
use device_manager::shm::ShmManager;
#[cfg(feature = "gpu")]
use devices::virtio::display::DisplayInfo;
#[cfg(feature = "gpu")]
use devices::virtio::display::NoopDisplayBackend;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::{VirtioShmRegion, fs::ExportTable};
use flate2::read::GzDecoder;
#[cfg(feature = "gpu")]
use krun_display::DisplayBackend;
#[cfg(feature = "gpu")]
use krun_display::IntoDisplayBackend;
#[cfg(feature = "amd-sev")]
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
#[cfg(target_arch = "x86_64")]
use linux_loader::loader::{self, KernelLoader};
use nix::unistd::isatty;
use polly::event_manager::{Error as EventManagerError, EventManager};
use utils::eventfd::EventFd;
use utils::worker_message::WorkerMessage;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use vm_memory::Address;
use vm_memory::Bytes;
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
use vm_memory::FileOffset;
#[cfg(not(feature = "aws-nitro"))]
use vm_memory::GuestMemory;
#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
use vm_memory::GuestRegionMmap;
#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
use vm_memory::mmap::MmapRegion;
use vm_memory::{GuestAddress, GuestMemoryMmap};

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
    /// The firmware can't be loaded into the provided memory address.
    FirmwareInvalidAddress(vm_memory::GuestMemoryError),
    /// Cannot read firmware contents from file.
    FirmwareRead(io::Error),
    /// Memory regions are overlapping or mmap fails.
    GuestMemoryMmap(String),
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
    /// The kernel doesn't fit into the microVM memory.
    KernelDoesNotFit(u64, usize),
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
    // Cannot initialize a MMIO Fs Device or add ad device to the MMIO Bus.
    RegisterConsoleDevice(device_manager::mmio::Error),
    /// Cannot register SIGWINCH event file descriptor.
    #[cfg(target_os = "linux")]
    RegisterFsSigwinch(kvm_ioctls::Error),
    /// Cannot initialize a MMIO Gpu device or add a device to the MMIO Bus.
    RegisterGpuDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Input device or add a device to the MMIO Bus.
    RegisterInputDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Network Device or add a device to the MMIO Bus.
    RegisterNetDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Rng device or add a device to the MMIO Bus.
    RegisterRngDevice(device_manager::mmio::Error),
    /// Cannot initialize a vhost-user device or add a device to the MMIO Bus.
    RegisterVhostUserDevice(device_manager::mmio::Error),
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
            FirmwareInvalidAddress(ref err) => {
                write!(
                    f,
                    "The firmware can't be loaded into the guest memory: {err}"
                )
            }
            FirmwareRead(ref err) => {
                write!(f, "Cannot read firmware contents from file: {err}")
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
            KernelDoesNotFit(load_addr, size) => write!(
                f,
                "The kernel doesn't fit in the microVM memory (load_addr={load_addr}, size={size})"
            ),
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
            RegisterConsoleDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot initialize a MMIO Console Device or add a device to the MMIO Bus. {err_msg}"
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
            RegisterInputDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Input Device or add a device to the MMIO Bus. {err_msg}"
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
            RegisterVhostUserDevice(ref err) => {
                let mut err_msg = err.to_string();
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a vhost-user device or add a device to the MMIO Bus. {err_msg}"
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
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Error obtaining the host address of an SHM region. {err_msg}"
                )
            }
            ShmConfig(ref err) => {
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");

                write!(f, "Error while configuring an SHM region. {err_msg}")
            }
            ShmCreate(ref err) => {
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");

                write!(f, "Error while creating an SHM region. {err_msg}")
            }
            InvalidTee => {
                write!(f, "TEE selected is not currently supported")
            }
        }
    }
}

pub enum Payload {
    #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
    KernelMmap,
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    KernelCopy,
    ExternalKernel(ExternalKernel),
    #[cfg(test)]
    Empty,
    Firmware,
    #[cfg(feature = "tee")]
    Tee,
}

pub fn choose_payload(
    kernel_bundle: Option<&crate::vmm_config::kernel_bundle::KernelBundle>,
    #[cfg(feature = "tee")] qboot_bundle: Option<&crate::vmm_config::kernel_bundle::QbootBundle>,
    #[cfg(feature = "tee")] initrd_bundle: Option<&crate::vmm_config::kernel_bundle::InitrdBundle>,
    external_kernel: Option<&crate::vmm_config::external_kernel::ExternalKernel>,
    firmware_config: Option<&crate::vmm_config::firmware::FirmwareConfig>,
) -> Result<Payload, StartMicrovmError> {
    if kernel_bundle.is_some() {
        #[cfg(feature = "tee")]
        if qboot_bundle.is_none() || initrd_bundle.is_none() {
            return Err(StartMicrovmError::MissingKernelConfig);
        }

        #[cfg(feature = "tee")]
        return Ok(Payload::Tee);

        #[cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "tee")))]
        return Ok(Payload::KernelMmap);

        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        return Ok(Payload::KernelCopy);
    } else if let Some(ek) = external_kernel {
        Ok(Payload::ExternalKernel(ek.clone()))
    } else if firmware_config.is_some() {
        Ok(Payload::Firmware)
    } else {
        Err(StartMicrovmError::MissingKernelConfig)
    }
}

// build_microvm has been replaced by the v2 API's VmmBuilder::build() in libkrun::api::vmm_builder.

fn load_external_kernel(
    guest_mem: &GuestMemoryMmap,
    arch_mem_info: &ArchMemoryInfo,
    external_kernel: &ExternalKernel,
) -> std::result::Result<(GuestAddress, Option<InitrdConfig>, Option<String>), StartMicrovmError> {
    let entry_addr = match external_kernel.format {
        // Raw images are treated as bundled kernels on x86_64
        #[cfg(target_arch = "x86_64")]
        KernelFormat::Raw => unreachable!(),
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
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
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        KernelFormat::PeGz => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::PeGzOpenKernel)?;
            if let Some(magic) = data
                .windows(3)
                .position(|window| window == [0x1f, 0x8b, 0x8])
            {
                debug!("Found GZIP header on PE file at: 0x{magic:x}");
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
                .windows(3)
                .position(|window| window == [b'B', b'Z', b'h'])
            {
                debug!("Found BZIP2 header on Image file at: 0x{magic:x}");
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
                debug!("Found GZIP header on Image file at: 0x{magic:x}");
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
                debug!("Found ZSTD header on Image file at: 0x{magic:x}");
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

pub fn load_payload(
    kernel_bundle: Option<&crate::vmm_config::kernel_bundle::KernelBundle>,
    #[cfg(feature = "tee")] qboot_bundle: Option<&crate::vmm_config::kernel_bundle::QbootBundle>,
    #[cfg(feature = "tee")] initrd_bundle: Option<&crate::vmm_config::kernel_bundle::InitrdBundle>,
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
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        Payload::KernelCopy => {
            let (kernel_entry_addr, kernel_host_addr, kernel_guest_addr, kernel_size) =
                if let Some(kb) = kernel_bundle {
                    (kb.entry_addr, kb.host_addr, kb.guest_addr, kb.size)
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };

            let kernel_data =
                unsafe { std::slice::from_raw_parts(kernel_host_addr as *mut u8, kernel_size) };
            if kernel_guest_addr + kernel_size as u64 > _arch_mem_info.ram_last_addr {
                return Err(StartMicrovmError::KernelDoesNotFit(
                    kernel_guest_addr,
                    kernel_size,
                ));
            }
            guest_mem
                .write(kernel_data, GuestAddress(kernel_guest_addr))
                .unwrap();
            Ok((guest_mem, GuestAddress(kernel_entry_addr), None, None))
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
        Payload::KernelMmap => {
            let (kernel_entry_addr, kernel_host_addr, kernel_guest_addr, kernel_size) =
                if let Some(kb) = kernel_bundle {
                    (kb.entry_addr, kb.host_addr, kb.guest_addr, kb.size)
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };

            #[cfg(all(feature = "vhost-user", target_os = "linux"))]
            let use_vhost_user = !_vm_resources.vhost_user_devices.is_empty();
            #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
            let use_vhost_user = false;

            let kernel_region = if use_vhost_user {
                #[cfg(all(feature = "vhost-user", target_os = "linux"))]
                {
                    debug!(
                        "Creating file-backed kernel region for vhost-user (size=0x{:x})",
                        kernel_size
                    );
                    // SAFETY: memfd_create is called with a valid null-terminated C string and valid flags.
                    // File descriptor ownership is transferred to File::from_raw_fd below.
                    let memfd = unsafe {
                        let fd = libc::memfd_create(c"kernel".as_ptr(), libc::MFD_CLOEXEC);
                        if fd < 0 {
                            error!(
                                "Failed to create memfd for kernel: {:?}",
                                io::Error::last_os_error()
                            );
                            return Err(StartMicrovmError::GuestMemoryMmap(format!(
                                "memfd_create failed: {:?}",
                                io::Error::last_os_error()
                            )));
                        }
                        if libc::ftruncate(fd, kernel_size as i64) < 0 {
                            error!(
                                "Failed to ftruncate kernel memfd: {:?}",
                                io::Error::last_os_error()
                            );
                            libc::close(fd);
                            return Err(StartMicrovmError::GuestMemoryMmap(format!(
                                "ftruncate failed: {:?}",
                                io::Error::last_os_error()
                            )));
                        }
                        debug!("Created kernel memfd with fd={}", fd);
                        File::from_raw_fd(fd)
                    };

                    let file_offset = FileOffset::new(memfd, 0);
                    let region = MmapRegion::from_file(file_offset, kernel_size)
                        .map_err(StartMicrovmError::InvalidKernelBundle)?;

                    // SAFETY: kernel_host_addr points to valid kernel data of size kernel_size,
                    // provided by the kernel bundle loader.
                    let kernel_data = unsafe {
                        std::slice::from_raw_parts(kernel_host_addr as *const u8, kernel_size)
                    };
                    // SAFETY: Both source (kernel_data) and destination (region) are valid for
                    // kernel_size bytes. Regions don't overlap as dest is newly allocated memfd-backed
                    // memory and source is from kernel bundle.
                    unsafe {
                        let dest = region.as_ptr() as *mut u8;
                        std::ptr::copy_nonoverlapping(kernel_data.as_ptr(), dest, kernel_size);
                    }
                    debug!("Copied kernel data to file-backed region");

                    region
                }
                #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
                unreachable!()
            } else {
                // SAFETY: kernel_host_addr points to valid kernel data of size kernel_size.
                // The memory region is managed by the kernel bundle and remains valid.
                unsafe {
                    MmapRegion::build_raw(kernel_host_addr as *mut u8, kernel_size, 0, 0)
                        .map_err(StartMicrovmError::InvalidKernelBundle)?
                }
            };

            Ok((
                guest_mem
                    .insert_region(Arc::new(
                        GuestRegionMmap::new(kernel_region, GuestAddress(kernel_guest_addr))
                            .ok_or_else(|| {
                                StartMicrovmError::GuestMemoryMmap(
                                    "Failed to create GuestRegionMmap".to_string(),
                                )
                            })?,
                    ))
                    .map_err(|e| StartMicrovmError::GuestMemoryMmap(format!("{e:?}")))?,
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
            let (kernel_host_addr, kernel_guest_addr, kernel_size) = if let Some(kb) = kernel_bundle
            {
                (kb.host_addr, kb.guest_addr, kb.size)
            } else {
                return Err(StartMicrovmError::MissingKernelConfig);
            };
            let kernel_data =
                unsafe { std::slice::from_raw_parts(kernel_host_addr as *mut u8, kernel_size) };
            guest_mem
                .write(kernel_data, GuestAddress(kernel_guest_addr))
                .unwrap();

            let (qboot_host_addr, qboot_size) = if let Some(qb) = qboot_bundle {
                (qb.host_addr, qb.size)
            } else {
                return Err(StartMicrovmError::MissingKernelConfig);
            };
            let qboot_data =
                unsafe { std::slice::from_raw_parts(qboot_host_addr as *mut u8, qboot_size) };
            guest_mem
                .write(qboot_data, GuestAddress(arch::FIRMWARE_START))
                .unwrap();

            let (initrd_host_addr, initrd_size) = if let Some(ib) = initrd_bundle {
                (ib.host_addr, ib.size)
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
        Payload::Firmware => Ok((guest_mem, GuestAddress(arch::RESET_VECTOR), None, None)),
    }
}

pub struct PayloadConfig {
    pub entry_addr: GuestAddress,
    pub initrd_config: Option<InitrdConfig>,
    pub kernel_cmdline: Option<String>,
}

pub fn create_guest_memory(
    mem_size_mib: usize,
    kernel_bundle: Option<&crate::vmm_config::kernel_bundle::KernelBundle>,
    #[cfg(feature = "tee")] qboot_bundle: Option<&crate::vmm_config::kernel_bundle::QbootBundle>,
    #[cfg(feature = "tee")] initrd_bundle: Option<&crate::vmm_config::kernel_bundle::InitrdBundle>,
    firmware_config: Option<&crate::vmm_config::firmware::FirmwareConfig>,
    fs_shm_sizes: &[Option<usize>],
    gpu_virgl_flags: Option<u32>,
    gpu_shm_size: Option<usize>,
    payload: &Payload,
) -> std::result::Result<
    (GuestMemoryMmap, ArchMemoryInfo, ShmManager, PayloadConfig),
    StartMicrovmError,
> {
    let mem_size = mem_size_mib << 20;

    let (firmware_data, firmware_size) = if let Some(firmware) = firmware_config {
        let data = std::fs::read(firmware.path.clone()).map_err(StartMicrovmError::FirmwareRead)?;
        let len = data.len();
        (Some(data), Some(len))
    } else {
        (None, None)
    };

    #[cfg(target_arch = "x86_64")]
    let (arch_mem_info, mut arch_mem_regions) = match payload {
        #[cfg(not(feature = "tee"))]
        Payload::KernelMmap => {
            let (kernel_guest_addr, kernel_size) = if let Some(kb) = kernel_bundle {
                (kb.guest_addr, kb.size)
            } else {
                return Err(StartMicrovmError::MissingKernelConfig);
            };
            arch::arch_memory_regions(mem_size, Some(kernel_guest_addr), kernel_size, 0, None)
        }
        Payload::ExternalKernel(external_kernel) => arch::arch_memory_regions(
            mem_size,
            None,
            0,
            external_kernel.initramfs_size,
            firmware_size,
        ),
        #[cfg(feature = "tee")]
        Payload::Tee => {
            let (kernel_guest_addr, kernel_size) = if let Some(kb) = kernel_bundle {
                (kb.guest_addr, kb.size)
            } else {
                return Err(StartMicrovmError::MissingKernelConfig);
            };
            arch::arch_memory_regions(mem_size, Some(kernel_guest_addr), kernel_size, 0, None)
        }
        #[cfg(test)]
        Payload::Empty => arch::arch_memory_regions(mem_size, None, 0, 0, None),
        Payload::Firmware => arch::arch_memory_regions(mem_size, None, 0, 0, firmware_size),
    };
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    let (arch_mem_info, mut arch_mem_regions) = match payload {
        Payload::ExternalKernel(external_kernel) => {
            arch::arch_memory_regions(mem_size, external_kernel.initramfs_size, None)
        }
        _ => arch::arch_memory_regions(mem_size, 0, firmware_size),
    };

    let mut shm_manager = ShmManager::new(&arch_mem_info);

    #[cfg(not(feature = "tee"))]
    for (index, shm_size) in fs_shm_sizes.iter().enumerate() {
        if let Some(shm_size) = shm_size {
            shm_manager
                .create_fs_region(index, *shm_size)
                .map_err(StartMicrovmError::ShmCreate)?;
        }
    }
    if gpu_virgl_flags.is_some() {
        let size = gpu_shm_size.unwrap_or(1 << 33);
        shm_manager
            .create_gpu_region(size)
            .map_err(StartMicrovmError::ShmCreate)?;
    }

    // For vhost-user devices, we need file-backed memory so the backend can mmap it
    #[cfg(all(feature = "vhost-user", target_os = "linux"))]
    let use_vhost_user = !vm_resources.vhost_user_devices.is_empty();
    #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
    let use_vhost_user = false;

    // Add SHM regions before creating guest memory
    arch_mem_regions.extend(shm_manager.regions());

    let guest_mem = if use_vhost_user {
        #[cfg(all(feature = "vhost-user", target_os = "linux"))]
        {
            debug!(
                "Creating file-backed memory for vhost-user (regions: {})",
                arch_mem_regions.len()
            );
            // Create file-backed memory regions using memfd
            let regions_with_files: Vec<_> = arch_mem_regions
                .iter()
                .map(|(addr, size)| {
                    debug!(
                        "Creating memfd for region: addr=0x{:x}, size=0x{:x}",
                        addr.0, size
                    );
                    // SAFETY: memfd_create is called with a valid null-terminated C string and valid flags.
                    // File descriptor ownership is transferred to File::from_raw_fd below.
                    let memfd = unsafe {
                        let fd = libc::memfd_create(c"guest_mem".as_ptr(), libc::MFD_CLOEXEC);
                        if fd < 0 {
                            error!("Failed to create memfd: {:?}", io::Error::last_os_error());
                            return Err(io::Error::last_os_error());
                        }
                        if libc::ftruncate(fd, *size as i64) < 0 {
                            error!(
                                "Failed to ftruncate memfd: {:?}",
                                io::Error::last_os_error()
                            );
                            libc::close(fd);
                            return Err(io::Error::last_os_error());
                        }
                        debug!("Created memfd with fd={}", fd);
                        File::from_raw_fd(fd)
                    };

                    let file_offset = FileOffset::new(memfd, 0);
                    Ok((*addr, *size, Some(file_offset)))
                })
                .collect::<Result<Vec<_>, io::Error>>()
                .map_err(|e| {
                    StartMicrovmError::GuestMemoryMmap(format!("memfd creation failed: {e:?}"))
                })?;

            debug!(
                "Created {} file-backed memory regions",
                regions_with_files.len()
            );
            GuestMemoryMmap::from_ranges_with_files(&regions_with_files)
                .map_err(|e| StartMicrovmError::GuestMemoryMmap(format!("{e:?}")))?
        }
        #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
        unreachable!()
    } else {
        GuestMemoryMmap::from_ranges(&arch_mem_regions)
            .map_err(|e| StartMicrovmError::GuestMemoryMmap(format!("{e:?}")))?
    };

    let (guest_mem, entry_addr, initrd_config, cmdline) = load_payload(
        kernel_bundle,
        #[cfg(feature = "tee")]
        qboot_bundle,
        #[cfg(feature = "tee")]
        initrd_bundle,
        guest_mem,
        &arch_mem_info,
        payload,
    )?;

    // Only write firmware if data exists AND this isn't an ExternalKernel payload
    // (ExternalKernel does direct kernel boot and doesn't use EFI firmware)
    if !matches!(payload, Payload::ExternalKernel(_)) {
        if let Some(firmware_data) = firmware_data.as_ref() {
            guest_mem
                .write(firmware_data, GuestAddress(arch_mem_info.firmware_addr))
                .map_err(StartMicrovmError::FirmwareInvalidAddress)?;
        }
    }

    let payload_config = PayloadConfig {
        entry_addr,
        initrd_config,
        kernel_cmdline: cmdline.clone(),
    };

    Ok((guest_mem, arch_mem_info, shm_manager, payload_config))
}

#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
pub fn load_cmdline(vmm: &Vmm) -> std::result::Result<(), StartMicrovmError> {
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
pub fn setup_vm(
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
pub fn setup_vm(
    kvm: &KvmContext,
    guest_memory: &GuestMemoryMmap,
    resources: &super::resources::VmResources,
    #[cfg(feature = "tdx")] _sender: Sender<WorkerMessage>,
) -> std::result::Result<Vm, StartMicrovmError> {
    let mut vm = Vm::new(
        kvm.fd(),
        resources.tee_config(),
        #[cfg(feature = "tdx")]
        _sender,
    )
    .map_err(Error::Vm)
    .map_err(StartMicrovmError::Internal)?;
    vm.memory_init(guest_memory, kvm.max_memslots())
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    Ok(vm)
}
#[cfg(target_os = "macos")]
pub fn setup_vm(
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
            warn!("Could not add serial input event to epoll: {e:?}");
        }
    }
    Ok(serial)
}

#[cfg(target_arch = "x86_64")]
pub fn attach_legacy_devices(
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

    register_irqfd_evt!(com_evt_1, 4);
    register_irqfd_evt!(com_evt_2, 3);
    register_irqfd_evt!(com_evt_3, 4);
    register_irqfd_evt!(com_evt_4, 3);
    register_irqfd_evt!(kbd_evt, 1);
    Ok(())
}

#[cfg(all(
    any(target_arch = "aarch64", target_arch = "riscv64"),
    target_os = "linux"
))]
pub fn attach_legacy_devices(
    vm: &Vm,
    mmio_device_manager: &mut MMIODeviceManager,
    kernel_cmdline: &mut kernel::cmdline::Cmdline,
    intc: IrqChip,
    serial: Vec<Arc<Mutex<Serial>>>,
) -> std::result::Result<(), StartMicrovmError> {
    for s in serial {
        mmio_device_manager
            .register_mmio_serial(vm.fd(), kernel_cmdline, intc.clone(), s)
            .map_err(Error::RegisterMMIODevice)
            .map_err(StartMicrovmError::Internal)?;
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    mmio_device_manager
        .register_mmio_rtc(vm.fd())
        .map_err(Error::RegisterMMIODevice)
        .map_err(StartMicrovmError::Internal)?;

    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
pub fn attach_legacy_devices(
    vm: &Vm,
    mmio_device_manager: &mut MMIODeviceManager,
    kernel_cmdline: &mut kernel::cmdline::Cmdline,
    intc: IrqChip,
    serial: Vec<Arc<Mutex<Serial>>>,
    event_manager: &mut EventManager,
    shutdown_efd: Option<EventFd>,
) -> Result<(), StartMicrovmError> {
    for s in serial {
        mmio_device_manager
            .register_mmio_serial(vm, kernel_cmdline, intc.clone(), s)
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
#[allow(clippy::too_many_arguments)]
pub fn create_vcpus_x86_64(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    guest_mem: &GuestMemoryMmap,
    entry_addr: GuestAddress,
    io_bus: &devices::Bus,
    exit_evt: &EventFd,
    kernel_boot: bool,
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

        vcpu.configure_x86_64(guest_mem, entry_addr, vcpu_config, kernel_boot, false)
            .map_err(Error::Vcpu)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub fn create_vcpus_aarch64(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    mem_info: &ArchMemoryInfo,
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

        vcpu.configure_aarch64(vm.fd(), mem_info, entry_addr)
            .map_err(Error::Vcpu)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
pub fn create_vcpus_aarch64(
    _vm: &Vm,
    vcpu_config: &VcpuConfig,
    mem_info: &ArchMemoryInfo,
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

        vcpu.configure_aarch64(mem_info).map_err(Error::Vcpu)?;

        if let Some(boot_sender) = boot_sender {
            boot_senders.insert(vcpu.get_mpidr(), boot_sender);
        }

        vcpus.push(vcpu);
    }

    vcpus[0].set_boot_senders(boot_senders);

    Ok(vcpus)
}

#[cfg(all(target_arch = "riscv64", target_os = "linux"))]
pub fn create_vcpus_riscv64(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    guest_mem: &GuestMemoryMmap,
    entry_addr: GuestAddress,
    exit_evt: &EventFd,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    for cpu_index in 0..vcpu_config.vcpu_count {
        let mut vcpu = Vcpu::new_riscv64(
            cpu_index,
            vm.fd(),
            exit_evt.try_clone().map_err(Error::EventFd)?,
        )
        .map_err(Error::Vcpu)?;

        vcpu.configure_riscv64(vm.fd(), guest_mem, entry_addr)
            .map_err(Error::Vcpu)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

/// Attaches an virtio mmio device to the device manager.
pub fn attach_mmio_device(
    vmm: &mut Vmm,
    id: String,
    intc: IrqChip,
    device: Arc<Mutex<dyn VirtioDevice>>,
) -> std::result::Result<(), device_manager::mmio::Error> {
    let mmio_device = MmioTransport::new(vmm.guest_memory().clone(), intc, device)?;

    let type_id = mmio_device.locked_device().device_type();
    let _cmdline = &mut vmm.kernel_cmdline;

    #[cfg(target_os = "linux")]
    let (_mmio_base, _irq) =
        vmm.mmio_device_manager
            .register_mmio_device(vmm.vm.fd(), mmio_device, type_id, id)?;
    #[cfg(target_os = "macos")]
    let (_mmio_base, _irq) =
        vmm.mmio_device_manager
            .register_mmio_device(mmio_device, type_id, id)?;

    #[cfg(target_arch = "x86_64")]
    vmm.mmio_device_manager
        .add_device_to_cmdline(_cmdline, _mmio_base, _irq)?;

    Ok(())
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
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
                config.read_only,
                config.virtual_entries.clone(),
            )
            .unwrap(),
        ));

        let id = format!("{}{}", String::from(fs.lock().unwrap().id()), i);

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
        attach_mmio_device(vmm, id, intc.clone(), fs).map_err(RegisterFsDevice)?;
    }

    Ok(())
}

fn autoconfigure_console_ports(
    vmm: &mut Vmm,
    _vm_resources: &VmResources,
    cfg: Option<&DefaultVirtioConsoleConfig>,
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    let (input_fd, output_fd, err_fd) = match cfg {
        Some(c) => (c.input_fd, c.output_fd, c.err_fd),
        None => (STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO),
    };
    {
        let input_is_terminal =
            input_fd >= 0 && isatty(unsafe { BorrowedFd::borrow_raw(input_fd) }).unwrap_or(false);
        let output_is_terminal =
            output_fd >= 0 && isatty(unsafe { BorrowedFd::borrow_raw(output_fd) }).unwrap_or(false);
        let error_is_terminal =
            err_fd >= 0 && isatty(unsafe { BorrowedFd::borrow_raw(err_fd) }).unwrap_or(false);

        let term_fd = if input_is_terminal {
            Some(unsafe { BorrowedFd::borrow_raw(input_fd) })
        } else if output_is_terminal {
            Some(unsafe { BorrowedFd::borrow_raw(output_fd) })
        } else if error_is_terminal {
            Some(unsafe { BorrowedFd::borrow_raw(err_fd) })
        } else {
            None
        };

        let forwarding_sigint;
        let console_input = if input_is_terminal && input_fd >= 0 {
            forwarding_sigint = false;
            Some(port_io::input_to_raw_fd_dup(input_fd).unwrap())
        } else {
            #[cfg(target_os = "linux")]
            {
                forwarding_sigint = true;
                let sigint_input = port_io::PortInputSigInt::new();
                let sigint_input_fd = sigint_input.sigint_evt().as_raw_fd();
                register_sigint_handler(sigint_input_fd)
                    .map_err(StartMicrovmError::RegisterFsSigwinch)?;
                Some(Box::new(sigint_input) as _)
            }
            #[cfg(not(target_os = "linux"))]
            {
                forwarding_sigint = false;
                Some(port_io::input_empty().unwrap())
            }
        };

        let console_output = if output_is_terminal && output_fd >= 0 {
            Some(port_io::output_to_raw_fd_dup(output_fd).unwrap())
        } else {
            Some(port_io::output_to_log_as_err())
        };

        let terminal_properties = term_fd
            .map(|fd| port_io::term_fd(fd.as_raw_fd()).unwrap())
            .unwrap_or_else(|| port_io::term_fixed_size(0, 0));

        setup_terminal_raw_mode(vmm, term_fd, forwarding_sigint);

        let mut ports = vec![PortDescription::console(
            console_input,
            console_output,
            terminal_properties,
        )];

        if input_fd >= 0 && !input_is_terminal {
            ports.push(PortDescription::input_pipe(
                "krun-stdin",
                port_io::input_to_raw_fd_dup(input_fd).unwrap(),
            ));
        }

        if output_fd >= 0 && !output_is_terminal {
            ports.push(PortDescription::output_pipe(
                "krun-stdout",
                port_io::output_to_raw_fd_dup(output_fd).unwrap(),
            ));
        };

        if err_fd >= 0 && !error_is_terminal {
            ports.push(PortDescription::output_pipe(
                "krun-stderr",
                port_io::output_to_raw_fd_dup(err_fd).unwrap(),
            ));
        }

        Ok(ports)
    }
}

pub fn setup_terminal_raw_mode(
    vmm: &mut Vmm,
    term_fd: Option<BorrowedFd<'_>>,
    handle_signals_by_terminal: bool,
) {
    if let Some(term_fd) = term_fd {
        match term_set_raw_mode(term_fd, handle_signals_by_terminal) {
            Ok(old_mode) => {
                let raw_fd = term_fd.as_raw_fd();
                vmm.exit_observers.push(Arc::new(Mutex::new(move || {
                    if let Err(e) =
                        term_restore_mode(unsafe { BorrowedFd::borrow_raw(raw_fd) }, &old_mode)
                    {
                        log::error!("Failed to restore terminal mode: {e}")
                    }
                })));
            }
            Err(e) => {
                log::error!("Failed to set terminal to raw mode: {e}")
            }
        };
    }
}

fn create_explicit_ports(
    vmm: &mut Vmm,
    port_configs: &[PortConfig],
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    let mut ports = Vec::with_capacity(port_configs.len());

    for port_cfg in port_configs {
        let port_desc = match port_cfg {
            PortConfig::Tty { name, tty_fd } => {
                assert!(*tty_fd > 0, "PortConfig::Tty must have a valid tty_fd");
                let term_fd = unsafe { BorrowedFd::borrow_raw(*tty_fd) };
                setup_terminal_raw_mode(vmm, Some(term_fd), false);

                PortDescription {
                    name: name.clone().into(),
                    input: Some(port_io::input_to_raw_fd_dup(*tty_fd).unwrap()),
                    output: Some(port_io::output_to_raw_fd_dup(*tty_fd).unwrap()),
                    terminal: Some(port_io::term_fd(*tty_fd).unwrap()),
                }
            }
            PortConfig::InOut {
                name,
                input_fd,
                output_fd,
            } => PortDescription {
                name: name.clone().into(),
                input: if *input_fd < 0 {
                    None
                } else {
                    Some(port_io::input_to_raw_fd_dup(*input_fd).unwrap())
                },
                output: if *output_fd < 0 {
                    None
                } else {
                    Some(port_io::output_to_raw_fd_dup(*output_fd).unwrap())
                },
                terminal: None,
            },
        };

        ports.push(port_desc);
    }

    Ok(ports)
}

fn attach_console_devices(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
    vm_resources: &VmResources,
    cfg: Option<&VirtioConsoleConfigMode>,
    id_number: u32,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let ports = match cfg {
        None => autoconfigure_console_ports(vmm, vm_resources, None)?,
        Some(VirtioConsoleConfigMode::Autoconfigure(autocfg)) => {
            autoconfigure_console_ports(vmm, vm_resources, Some(autocfg))?
        }
        Some(VirtioConsoleConfigMode::Explicit(ports)) => create_explicit_ports(vmm, ports)?,
    };

    let console = Arc::new(Mutex::new(devices::virtio::Console::new(ports).unwrap()));

    vmm.exit_observers.push(console.clone());

    event_manager
        .add_subscriber(console.clone())
        .map_err(RegisterEvent)?;

    #[cfg(target_os = "linux")]
    register_sigwinch_handler(console.lock().unwrap().get_sigwinch_fd())
        .map_err(RegisterFsSigwinch)?;

    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_mmio_device(vmm, format!("hvc{id_number}"), intc, console)
        .map_err(RegisterConsoleDevice)?;

    Ok(())
}

#[cfg(not(feature = "tee"))]
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
fn attach_vhost_user_device(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
    device_config: &VhostUserDeviceConfig,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let device_name = device_config
        .name
        .clone()
        .unwrap_or_else(|| format!("vhost-user-{}", device_config.device_type));

    let device = Arc::new(Mutex::new(
        devices::virtio::VhostUserDevice::new(
            &device_config.socket_path,
            device_config.device_type,
            device_name.clone(),
            device_config.num_queues,
            &device_config.queue_sizes,
        )
        .map_err(|e| RegisterVhostUserDevice(device_manager::mmio::Error::VhostUserDevice(e)))?,
    ));

    event_manager
        .add_subscriber(device.clone())
        .map_err(RegisterEvent)?;

    attach_mmio_device(vmm, device_name, intc.clone(), device).map_err(RegisterVhostUserDevice)?;

    Ok(())
}

#[cfg(feature = "gpu")]
#[allow(clippy::too_many_arguments)]
fn attach_gpu_device(
    vmm: &mut Vmm,
    shm_manager: &mut ShmManager,
    #[cfg(not(feature = "tee"))] mut export_table: Option<ExportTable>,
    intc: IrqChip,
    virgl_flags: u32,
    displays: Box<[DisplayInfo]>,
    display_backend: DisplayBackend<'static>,
    #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let gpu = Arc::new(Mutex::new(
        devices::virtio::Gpu::new(
            virgl_flags,
            displays,
            display_backend,
            #[cfg(target_os = "macos")]
            map_sender,
        )
        .unwrap(),
    ));

    let id = String::from(gpu.lock().unwrap().id());

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
    attach_mmio_device(vmm, id, intc, gpu).map_err(RegisterGpuDevice)?;

    Ok(())
}

#[cfg(feature = "input")]
fn attach_input_devices(
    vmm: &mut Vmm,
    input_backends: &[(
        krun_input::InputConfigBackend<'static>,
        krun_input::InputEventProviderBackend<'static>,
    )],
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    for (index, (config_backend, events_backend)) in input_backends.iter().enumerate() {
        let input_device = Arc::new(Mutex::new(
            devices::virtio::input::Input::new(*config_backend, *events_backend).unwrap(),
        ));

        let id = format!("input{}", index);
        attach_mmio_device(vmm, id, intc.clone(), input_device).map_err(RegisterInputDevice)?;
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::vmm_config::kernel_bundle::KernelBundle;

    #[allow(unused)]
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

        create_guest_memory(mem_size_mib, &vm_resources, &Payload::Empty)
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_create_vcpus_x86_64() {
        let vcpu_count = 2;

        let vcpu_config = VcpuConfig {
            vcpu_count,
            ht_enabled: false,
            cpu_template: None,
            nested_enabled: false,
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
            true,
        )
        .unwrap();
        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }

    #[test]
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn test_create_vcpus_aarch64() {
        let (guest_memory, arch_memory_info, _shm_manager, _payload_config) =
            default_guest_memory(128).unwrap();
        let vm = setup_vm(&guest_memory, false).unwrap();
        let vcpu_count = 2;

        let vcpu_config = VcpuConfig {
            vcpu_count,
            ht_enabled: false,
            cpu_template: None,
            nested_enabled: false,
        };

        // Dummy entry_addr, vcpus will not boot.
        let entry_addr = GuestAddress(0);
        let vcpu_vec = create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
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
        let _ = format!("{err}{err:?}");

        let err = CreateRateLimiter(io::Error::from_raw_os_error(0));
        let _ = format!("{err}{err:?}");

        let err = Internal(Error::Serial(io::Error::from_raw_os_error(0)));
        let _ = format!("{err}{err:?}");

        let err = InvalidKernelBundle(vm_memory::mmap::MmapRegionError::InvalidPointer);
        let _ = format!("{err}{err:?}");

        let err = KernelCmdline(String::from("dummy --cmdline"));
        let _ = format!("{err}{err:?}");

        let err = LoadCommandline(kernel::cmdline::Error::TooLarge);
        let _ = format!("{err}{err:?}");

        let err = MicroVMAlreadyRunning;
        let _ = format!("{err}{err:?}");

        let err = MissingKernelConfig;
        let _ = format!("{err}{err:?}");

        let err = MissingMemSizeConfig;
        let _ = format!("{err}{err:?}");

        let err = NetDeviceNotConfigured;
        let _ = format!("{err}{err:?}");

        let err = OpenBlockDevice(io::Error::from_raw_os_error(0));
        let _ = format!("{err}{err:?}");

        let err = RegisterBlockDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{err}{err:?}");

        let err = RegisterEvent(EventManagerError::EpollCreate(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{err}{err:?}");

        let err = RegisterNetDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{err}{err:?}");

        let err = RegisterVsockDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{err}{err:?}");
    }

    #[test]
    fn test_kernel_cmdline_err_to_startuvm_err() {
        let err = StartMicrovmError::from(kernel::cmdline::Error::HasSpace);
        let _ = format!("{err}{err:?}");
    }
}

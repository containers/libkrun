// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::borrowed_box)]

mod fdt;
/// Layout for this aarch64 system.
pub mod layout;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::*;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::*;

use std::collections::HashMap;
use std::fmt::Debug;

use self::gic::GICDevice;
use crate::{round_up, ArchMemoryInfo};
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap};

#[cfg(feature = "efi")]
use smbios;

/// Errors thrown while configuring aarch64 system.
#[derive(Debug)]
pub enum Error {
    /// Failed to create a Flattened Device Tree for this aarch64 microVM.
    SetupFDT(fdt::Error),
    /// Failed to compute the initrd address.
    InitrdAddress,

    #[cfg(feature = "efi")]
    /// SMBIOS Error
    Smbios(smbios::Error),
}

/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = layout::MAPPED_IO_START;

pub use self::fdt::DeviceInfoForFDT;
use crate::DeviceType;

/// Returns a Vec of the valid memory addresses for aarch64.
/// See [`layout`](layout) module for a drawing of the specific memory model for this platform.
pub fn arch_memory_regions(
    size: usize,
    initrd_size: u64,
) -> (ArchMemoryInfo, Vec<(GuestAddress, usize)>) {
    let page_size: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() };
    let dram_size = round_up(size, page_size);
    let ram_last_addr = layout::DRAM_MEM_START + (dram_size as u64);
    let shm_start_addr = ((ram_last_addr / 0x4000_0000) + 1) * 0x4000_0000;

    let info = ArchMemoryInfo {
        ram_last_addr,
        shm_start_addr,
        page_size,
        initrd_addr: ram_last_addr - layout::FDT_MAX_SIZE as u64 - initrd_size,
    };
    let regions = if cfg!(feature = "efi") {
        vec![
            // Space for loading EDK2 and its variables
            (GuestAddress(0u64), 0x800_0000),
            (GuestAddress(layout::DRAM_MEM_START), dram_size),
        ]
    } else {
        vec![(GuestAddress(layout::DRAM_MEM_START), dram_size)]
    };

    (info, regions)
}

/// Configures the system and should be called once per vm before starting vcpu threads.
/// For aarch64, we only setup the FDT.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_cstring` - The kernel commandline.
/// * `vcpu_mpidr` - Array of MPIDR register values per vcpu.
/// * `device_info` - A hashmap containing the attached devices for building FDT device nodes.
/// * `gic_device` - The GIC device.
/// * `initrd` - Information about an optional initrd.
#[allow(clippy::too_many_arguments)]
pub fn configure_system<T: DeviceInfoForFDT + Clone + Debug>(
    guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
    cmdline_cstring: &str,
    vcpu_mpidr: Vec<u64>,
    device_info: &HashMap<(DeviceType, String), T>,
    gic_device: &Box<dyn GICDevice>,
    initrd: &Option<super::InitrdConfig>,
    _smbios_oem_strings: &Option<Vec<String>>,
) -> super::Result<()> {
    fdt::create_fdt(
        guest_mem,
        arch_memory_info,
        vcpu_mpidr,
        cmdline_cstring,
        device_info,
        gic_device,
        initrd,
    )
    .map_err(Error::SetupFDT)?;

    #[cfg(feature = "efi")]
    smbios::setup_smbios(guest_mem, layout::SMBIOS_START, _smbios_oem_strings)
        .map_err(Error::Smbios)?;

    Ok(())
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::DRAM_MEM_START
}

/// Returns the memory address where the initrd could be loaded.
pub fn initrd_load_addr(guest_mem: &GuestMemoryMmap, initrd_size: usize) -> super::Result<u64> {
    let round_to_pagesize = |size| (size + (super::PAGE_SIZE - 1)) & !(super::PAGE_SIZE - 1);
    match GuestAddress(get_fdt_addr(guest_mem)).checked_sub(round_to_pagesize(initrd_size) as u64) {
        Some(offset) => {
            if guest_mem.address_in_range(offset) {
                Ok(offset.raw_value())
            } else {
                Err(Error::InitrdAddress)
            }
        }
        None => Err(Error::InitrdAddress),
    }
}

// Auxiliary function to get the address where the device tree blob is loaded.
pub fn get_fdt_addr(_mem: &GuestMemoryMmap) -> u64 {
    // If the memory allocated is smaller than the size allocated for the FDT,
    // we return the start of the DRAM so that
    // we allow the code to try and load the FDT.

    #[cfg(not(feature = "efi"))]
    if let Some(addr) = _mem
        .last_addr()
        .checked_sub(layout::FDT_MAX_SIZE as u64 - 1)
    {
        if _mem.address_in_range(addr) {
            return addr.raw_value();
        }
    }

    layout::DRAM_MEM_START
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regions_lt_1024gb() {
        let (_mem_info, regions) = arch_memory_regions(1usize << 29);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn test_regions_gt_1024gb() {
        let (_mem_info, regions) = arch_memory_regions(1usize << 41);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(super::layout::DRAM_MEM_MAX_SIZE, regions[0].1 as u64);
    }

    #[test]
    fn test_get_fdt_addr() {
        let (_mem_info, regions) = arch_memory_regions(layout::FDT_MAX_SIZE - 0x1000);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let (_mem_info, regions) = arch_memory_regions(layout::FDT_MAX_SIZE);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let (_mem_info, regions) = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), 0x1000 + layout::DRAM_MEM_START);
    }
}

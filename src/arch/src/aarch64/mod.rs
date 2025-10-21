// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::borrowed_box)]

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

use std::fmt::Debug;

use crate::{aarch64::layout::FIRMWARE_START, ArchMemoryInfo};
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap};
use vmm_sys_util::align_upwards;

use smbios;

/// Errors thrown while configuring aarch64 system.
#[derive(Debug)]
pub enum Error {
    /// Failed to compute the initrd address.
    InitrdAddress,

    /// SMBIOS Error
    Smbios(smbios::Error),
}

/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = layout::MAPPED_IO_START;

/// Returns a Vec of the valid memory addresses for aarch64.
/// See [`layout`](layout) module for a drawing of the specific memory model for this platform.
pub fn arch_memory_regions(
    size: usize,
    initrd_size: u64,
    firmware_size: Option<usize>,
) -> (ArchMemoryInfo, Vec<(GuestAddress, usize)>) {
    let page_size: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() };
    // align up, then cap to the maximum allowed DRAM size
    let aligned = align_upwards!(size, page_size);
    let dram_size = {
        let capped = core::cmp::min(aligned as u64, layout::DRAM_MEM_MAX_SIZE);
        capped as usize
    };
    let ram_last_addr = layout::DRAM_MEM_START + (dram_size as u64);
    let shm_start_addr = ((ram_last_addr / 0x4000_0000) + 1) * 0x4000_0000;

    let info = ArchMemoryInfo {
        ram_last_addr,
        shm_start_addr,
        page_size,
        initrd_addr: ram_last_addr - layout::FDT_MAX_SIZE as u64 - initrd_size,
        firmware_addr: FIRMWARE_START,
    };
    let regions = if let Some(firmware_size) = firmware_size {
        vec![
            // Space for loading the firmware
            (GuestAddress(0u64), align_upwards!(firmware_size, page_size)),
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
pub fn configure_system(
    _guest_mem: &GuestMemoryMmap,
    _smbios_oem_strings: &Option<Vec<String>>,
) -> super::Result<()> {
    smbios::setup_smbios(_guest_mem, layout::SMBIOS_START, _smbios_oem_strings)
        .map_err(Error::Smbios)?;

    Ok(())
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::DRAM_MEM_START
}

/// Returns the memory address where the initrd could be loaded.
pub fn initrd_load_addr(guest_mem: &GuestMemoryMmap, initrd_size: usize) -> super::Result<u64> {
    match GuestAddress(get_fdt_addr(guest_mem))
        .checked_sub(align_upwards!(initrd_size, super::PAGE_SIZE) as u64)
    {
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
pub fn get_fdt_addr(mem: &GuestMemoryMmap) -> u64 {
    // Put FDT at the beginning of DRAM while the RAM region is small (<= FDT_MAX_SIZE)
    // For larger guests, move it by one page to avoid overlapping early allocations.
    let dram_end = mem.last_addr().raw_value();
    let dram_size = dram_end.saturating_sub(layout::DRAM_MEM_START) + 1;
    if dram_size > layout::FDT_MAX_SIZE as u64 {
        layout::DRAM_MEM_START + 0x1000
    } else {
        layout::DRAM_MEM_START
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regions_lt_1024gb() {
        let (_mem_info, regions) = arch_memory_regions(1usize << 29, 0);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn test_regions_gt_1024gb() {
        let (_mem_info, regions) = arch_memory_regions(1usize << 41, 0);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(super::layout::DRAM_MEM_START), regions[0].0);
        assert_eq!(super::layout::DRAM_MEM_MAX_SIZE, regions[0].1 as u64);
    }

    #[test]
    fn test_get_fdt_addr() {
        let (_mem_info, regions) = arch_memory_regions(layout::FDT_MAX_SIZE - 0x1000, 0);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let (_mem_info, regions) = arch_memory_regions(layout::FDT_MAX_SIZE, 0);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), layout::DRAM_MEM_START);

        let (_mem_info, regions) = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000, 0);
        let mem = GuestMemoryMmap::from_ranges(&regions).expect("Cannot initialize memory");
        assert_eq!(get_fdt_addr(&mem), 0x1000 + layout::DRAM_MEM_START);
    }
}

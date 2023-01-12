// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod gdt;
/// Contains logic for setting up Advanced Programmable Interrupt Controller (local version).
pub mod interrupts;
/// Layout for the x86_64 system.
pub mod layout;
#[cfg(not(feature = "tee"))]
mod mptable;
/// Logic for configuring x86_64 model specific registers (MSRs).
pub mod msr;
/// Logic for configuring x86_64 registers.
pub mod regs;

use crate::ArchMemoryInfo;
use crate::InitrdConfig;
use arch_gen::x86::bootparam::{boot_params, E820_RAM};
use vm_memory::Bytes;
use vm_memory::{
    Address, ByteValued, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
};

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `ByteValued`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct BootParamsWrapper(boot_params);

// It is safe to initialize BootParamsWrap which is a wrapper over `boot_params` (a series of ints).
unsafe impl ByteValued for BootParamsWrapper {}

/// Errors thrown while configuring x86_64 system.
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid e820 setup params.
    E820Configuration,
    /// Error writing MP table to memory.
    #[cfg(not(feature = "tee"))]
    MpTableSetup(mptable::Error),
    /// Error writing the zero page of guest memory.
    ZeroPageSetup,
    /// Failed to compute initrd address.
    InitrdAddress,
}

// Where BIOS/VGA magic would live on a real PC.
const EBDA_START: u64 = 0x9fc00;
pub const RESET_VECTOR: u64 = 0xfff0;
pub const RESET_VECTOR_SEV_AP: u64 = 0xfff3;
pub const BIOS_START: u64 = 0xffff_0000;
pub const BIOS_SIZE: usize = 65536;
const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;
/// The size of the MMIO shared memory area used by virtio-fs DAX.
pub const MMIO_SHM_SIZE: u64 = 1 << 29;

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemoryMmap structure for the platform.
/// Make a hole for the kernel region that will be injected directly from libkrunfw's
/// mapping, and reserve an SHM region for virtio-fs.
#[cfg(not(feature = "tee"))]
pub fn arch_memory_regions(
    size: usize,
    kernel_load_addr: u64,
    kernel_size: usize,
) -> (ArchMemoryInfo, Vec<(GuestAddress, usize)>) {
    if size < (kernel_load_addr + kernel_size as u64) as usize {
        panic!("Kernel doesn't fit in RAM");
    }

    // It's safe to cast MMIO_MEM_START to usize because it fits in a u32 variable
    // (It points to an address in the 32 bit space).
    let (ram_last_addr, shm_start_addr, regions) = match size.checked_sub(MMIO_MEM_START as usize) {
        // case1: guest memory fits before the gap
        None | Some(0) => {
            let ram_last_addr = kernel_load_addr + kernel_size as u64 + size as u64;
            let shm_start_addr = FIRST_ADDR_PAST_32BITS;
            (
                ram_last_addr,
                shm_start_addr,
                vec![
                    (GuestAddress(0), kernel_load_addr as usize),
                    (GuestAddress(kernel_load_addr + kernel_size as u64), size),
                    (GuestAddress(FIRST_ADDR_PAST_32BITS), MMIO_SHM_SIZE as usize),
                ],
            )
        }
        // case2: guest memory extends beyond the gap
        Some(remaining) => {
            let ram_last_addr = FIRST_ADDR_PAST_32BITS + remaining as u64;
            let shm_start_addr = ((ram_last_addr / 0x4000_0000) + 1) * 0x4000_0000;
            (
                ram_last_addr,
                shm_start_addr,
                vec![
                    (GuestAddress(0), kernel_load_addr as usize),
                    (
                        GuestAddress(kernel_load_addr + kernel_size as u64),
                        (MMIO_MEM_START - (kernel_load_addr + kernel_size as u64)) as usize,
                    ),
                    (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
                    (GuestAddress(shm_start_addr), MMIO_SHM_SIZE as usize),
                ],
            )
        }
    };
    let info = ArchMemoryInfo {
        ram_last_addr,
        shm_start_addr,
        shm_size: MMIO_SHM_SIZE,
    };
    (info, regions)
}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemoryMmap structure for the platform.
/// For SEV, don't make a hole for the kernel, as it needs to be copied instead of injected,
/// don't reserve an SHM region, as virtio-fs is not supported, and reserve a small 64K
/// region for the BIOS.
#[cfg(feature = "tee")]
pub fn arch_memory_regions(
    size: usize,
    kernel_load_addr: u64,
    kernel_size: usize,
) -> (ArchMemoryInfo, Vec<(GuestAddress, usize)>) {
    if size < (kernel_load_addr + kernel_size as u64) as usize {
        panic!("Kernel doesn't fit in RAM");
    }

    // It's safe to cast MMIO_MEM_START to usize because it fits in a u32 variable
    // (It points to an address in the 32 bit space).
    let (ram_last_addr, shm_start_addr, regions) = match size.checked_sub(MMIO_MEM_START as usize) {
        // case1: guest memory fits before the gap
        None | Some(0) => {
            let ram_last_addr = size as u64;
            let shm_start_addr = 0u64;
            (
                ram_last_addr,
                shm_start_addr,
                vec![
                    (GuestAddress(0), size),
                    (GuestAddress(BIOS_START), BIOS_SIZE),
                ],
            )
        }
        // case2: guest memory extends beyond the gap
        Some(remaining) => {
            let ram_last_addr = FIRST_ADDR_PAST_32BITS + remaining as u64;
            let shm_start_addr = 0u64;
            (
                ram_last_addr,
                shm_start_addr,
                vec![
                    (GuestAddress(0), MMIO_MEM_START as usize),
                    (GuestAddress(BIOS_START), BIOS_SIZE),
                    (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
                ],
            )
        }
    };
    let info = ArchMemoryInfo {
        ram_last_addr,
        shm_start_addr,
        shm_size: 0,
    };
    (info, regions)
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> u64 {
    layout::HIMEM_START
}

/// Returns the memory address where the initrd could be loaded.
pub fn initrd_load_addr(guest_mem: &GuestMemoryMmap, initrd_size: usize) -> super::Result<u64> {
    let first_region = guest_mem
        .find_region(GuestAddress::new(0))
        .ok_or(Error::InitrdAddress)?;
    // It's safe to cast to usize because the size of a region can't be greater than usize.
    let lowmem_size = first_region.len() as usize;

    if lowmem_size < initrd_size {
        return Err(Error::InitrdAddress);
    }

    let align_to_pagesize = |address| address & !(super::PAGE_SIZE - 1);
    Ok(align_to_pagesize(lowmem_size - initrd_size) as u64)
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
/// * `initrd` - Information about where the ramdisk image was loaded in the `guest_mem`.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
#[allow(unused_variables)]
pub fn configure_system(
    guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: &Option<InitrdConfig>,
    num_cpus: u8,
) -> super::Result<()> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000; // Must be non-zero.
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(MMIO_MEM_START);

    let himem_start = GuestAddress(layout::HIMEM_START);

    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    #[cfg(not(feature = "tee"))]
    mptable::setup_mptable(guest_mem, num_cpus).map_err(Error::MpTableSetup)?;

    let mut params: BootParamsWrapper = BootParamsWrapper(boot_params::default());

    params.0.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.0.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.0.hdr.header = KERNEL_HDR_MAGIC;
    params.0.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    params.0.hdr.cmdline_size = cmdline_size as u32;

    params.0.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    if let Some(initrd_config) = initrd {
        params.0.hdr.ramdisk_image = initrd_config.address.raw_value() as u32;
        params.0.hdr.ramdisk_size = initrd_config.size as u32;
    }

    #[cfg(feature = "tee")]
    {
        params.0.hdr.syssize = num_cpus as u32;
    }

    add_e820_entry(&mut params.0, 0, EBDA_START, E820_RAM)?;

    let last_addr = GuestAddress(arch_memory_info.ram_last_addr);
    if last_addr < end_32bit_gap_start {
        add_e820_entry(
            &mut params.0,
            himem_start.raw_value(),
            // it's safe to use unchecked_offset_from because
            // mem_end > himem_start
            last_addr.unchecked_offset_from(himem_start) + 1,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params.0,
            himem_start.raw_value(),
            // it's safe to use unchecked_offset_from because
            // end_32bit_gap_start > himem_start
            end_32bit_gap_start.unchecked_offset_from(himem_start),
            E820_RAM,
        )?;

        if last_addr > first_addr_past_32bits {
            add_e820_entry(
                &mut params.0,
                first_addr_past_32bits.raw_value(),
                // it's safe to use unchecked_offset_from because
                // mem_end > first_addr_past_32bits
                last_addr.unchecked_offset_from(first_addr_past_32bits) + 1,
                E820_RAM,
            )?;
        }
    }

    let zero_page_addr = GuestAddress(layout::ZERO_PAGE_START);
    guest_mem
        .write_obj(params, zero_page_addr)
        .map_err(|_| Error::ZeroPageSetup)?;

    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> super::Result<()> {
    if params.e820_entries >= params.e820_map.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_map[params.e820_entries as usize].addr = addr;
    params.e820_map[params.e820_entries as usize].size = size;
    params.e820_map[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arch_gen::x86::bootparam::e820entry;

    const KERNEL_LOAD_ADDR: u64 = 0x0100_0000;
    const KERNEL_SIZE: usize = 0x01E0_0000;

    #[test]
    fn regions_lt_4gb() {
        let (_info, regions) = arch_memory_regions(1usize << 29, KERNEL_LOAD_ADDR, KERNEL_SIZE);
        assert_eq!(3, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(KERNEL_LOAD_ADDR as usize, regions[0].1);
        assert_eq!(
            GuestAddress(KERNEL_LOAD_ADDR + KERNEL_SIZE as u64),
            regions[1].0
        );
        assert_eq!(1usize << 29, regions[1].1);
    }

    #[test]
    fn regions_gt_4gb() {
        let (_info, regions) =
            arch_memory_regions((1usize << 32) + 0x8000, KERNEL_LOAD_ADDR, KERNEL_SIZE);
        assert_eq!(4, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(KERNEL_LOAD_ADDR as usize, regions[0].1);
        assert_eq!(
            GuestAddress(KERNEL_LOAD_ADDR + KERNEL_SIZE as u64),
            regions[1].0
        );
        assert_eq!(GuestAddress(1u64 << 32), regions[2].0);
    }

    #[test]
    fn test_system_configuration() {
        let no_vcpus = 4;
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let info = ArchMemoryInfo::default();
        let config_err = configure_system(&gm, &info, GuestAddress(0), 0, &None, 1);
        assert!(config_err.is_err());
        #[cfg(not(feature = "tee"))]
        assert_eq!(
            config_err.unwrap_err(),
            super::Error::MpTableSetup(mptable::Error::NotEnoughMemory)
        );

        // Now assigning some memory that falls before the 32bit memory hole.
        let mem_size = 128 << 20;
        let (arch_mem_info, arch_mem_regions) =
            arch_memory_regions(mem_size, KERNEL_LOAD_ADDR, KERNEL_SIZE);
        let gm = GuestMemoryMmap::from_ranges(&arch_mem_regions).unwrap();
        configure_system(&gm, &arch_mem_info, GuestAddress(0), 0, &None, no_vcpus).unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let mem_size = 3328 << 20;
        let (arch_mem_info, arch_mem_regions) =
            arch_memory_regions(mem_size, KERNEL_LOAD_ADDR, KERNEL_SIZE);
        let gm = GuestMemoryMmap::from_ranges(&arch_mem_regions).unwrap();
        configure_system(&gm, &arch_mem_info, GuestAddress(0), 0, &None, no_vcpus).unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let mem_size = 3330 << 20;
        let (arch_mem_info, arch_mem_regions) =
            arch_memory_regions(mem_size, KERNEL_LOAD_ADDR, KERNEL_SIZE);
        let gm = GuestMemoryMmap::from_ranges(&arch_mem_regions).unwrap();
        configure_system(&gm, &arch_mem_info, GuestAddress(0), 0, &None, no_vcpus).unwrap();
    }

    #[test]
    fn test_add_e820_entry() {
        let e820_map = [(e820entry {
            addr: 0x1,
            size: 4,
            type_: 1,
        }); 128];

        let expected_params = boot_params {
            e820_map,
            e820_entries: 1,
            ..Default::default()
        };

        let mut params: boot_params = Default::default();
        add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_,
        )
        .unwrap();
        assert_eq!(
            format!("{:?}", params.e820_map[0]),
            format!("{:?}", expected_params.e820_map[0])
        );
        assert_eq!(params.e820_entries, expected_params.e820_entries);

        // Exercise the scenario where the field storing the length of the e820 entry table is
        // is bigger than the allocated memory.
        params.e820_entries = params.e820_map.len() as u8 + 1;
        assert!(add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_
        )
        .is_err());
    }
}

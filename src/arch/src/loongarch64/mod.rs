/// Layout for this loongarch64 system.
pub mod layout;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::*;

use crate::{loongarch64::layout::FIRMWARE_START, ArchMemoryInfo};
use vm_memory::{GuestAddress, GuestMemoryMmap};
use vmm_sys_util::align_upwards;

/// Errors thrown while configuring loongarch64 system.
#[derive(Debug)]
pub enum Error {
    /// Failed to compute the initrd address.
    InitrdAddress,
    /// Failed to setup EFI system table in the FDT.
    EfiSystemTable(linux::efi::Error),
}

/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = layout::MAPPED_IO_START;

/// Returns a Vec of the valid memory addresses for loongarch64.
pub fn arch_memory_regions(
    size: usize,
    initrd_size: u64,
    _firmware_size: Option<usize>,
) -> (ArchMemoryInfo, Vec<(GuestAddress, usize)>) {
    let page_size: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() };
    let dram_size = align_upwards!(size, page_size);
    let ram_last_addr = layout::DRAM_MEM_START + (dram_size as u64);
    // Align SHM start to 1GiB boundaries without forcing an extra 1GiB gap
    // when RAM already ends at an aligned boundary.
    let shm_start_addr = align_upwards!(ram_last_addr, 0x4000_0000u64);

    let fdt_addr = ram_last_addr - layout::FDT_MAX_SIZE as u64;
    let efi_system_table_addr = fdt_addr - layout::EFI_GUEST_SIZE;
    let initrd_addr = efi_system_table_addr - initrd_size;
    let info = ArchMemoryInfo {
        ram_last_addr,
        shm_start_addr,
        page_size,
        fdt_addr,
        efi_system_table_addr,
        initrd_addr,
        firmware_addr: FIRMWARE_START,
    };
    let regions = vec![(GuestAddress(layout::DRAM_MEM_START), dram_size)];

    (info, regions)
}

/// Configures the system and should be called once per vm before starting vcpu threads.
pub fn configure_system(
    _guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
    _smbios_oem_strings: &Option<Vec<String>>,
) -> super::Result<()> {
    linux::efi::setup_fdt_system_table(_guest_mem, arch_memory_info)
        .map_err(Error::EfiSystemTable)?;
    Ok(())
}

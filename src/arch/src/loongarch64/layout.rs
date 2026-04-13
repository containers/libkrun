/// Start of RAM on LoongArch.
pub const DRAM_MEM_START: u64 = 0x4000_0000; // 1GB

/// The maximum addressable RAM address.
pub const DRAM_MEM_END: u64 = 0x00FF_8000_0000; // 1022GB

/// The maximum RAM size.
pub const DRAM_MEM_MAX_SIZE: u64 = DRAM_MEM_END - DRAM_MEM_START;

/// Kernel command line maximum size.
pub const CMDLINE_MAX_SIZE: usize = 2048;

/// Kernel command line args size
pub const CMDLINE_GUEST_SIZE: u64 = 0x4000;

/// Usable CPU hardware interrupt range on LoongArch.
///
/// The current virt platform injects serial/virtio interrupts through
/// `cpuintc + KVM_INTERRUPT`, so keep the MMIO allocator inside INT_HWI0..7.
pub const IRQ_BASE: u32 = 2;
pub const IRQ_MAX: u32 = 9;

/// Below this address will reside MMIO devices.
pub const MAPPED_IO_START: u64 = 0x0a00_0000;

/// Where the PC register will point after reset.
pub const RESET_VECTOR: u64 = 0;

/// The address to load firmware, if present.
pub const FIRMWARE_START: u64 = 0;

/// FDT maximum size.
pub const FDT_MAX_SIZE: usize = 0x1_0000;

/// EFI Guest size.
pub const EFI_GUEST_SIZE: u64 = 0x4000;

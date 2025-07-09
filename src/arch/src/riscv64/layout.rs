// Copyright 2025 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Start of RAM on 64 bit RISC-V.
#[cfg(not(feature = "efi"))]
pub const DRAM_MEM_START: u64 = 0x8000_0000; // 2 GB.
#[cfg(feature = "efi")]
pub const DRAM_MEM_START: u64 = 0x4000_0000; // 1 GB.
/// The maximum addressable RAM address.
pub const DRAM_MEM_END: u64 = 0x00FF_8000_0000; // 1024 - 2 = 1022 GB.
/// The maximum RAM size.
pub const DRAM_MEM_MAX_SIZE: u64 = DRAM_MEM_END - DRAM_MEM_START;

/// Kernel command line maximum size.
/// As per `arch/riscv/include/uapi/asm/setup.h`.
pub const CMDLINE_MAX_SIZE: usize = 1024;

pub const FDT_MAX_SIZE: usize = 0x1_0000;

/// First usable interrupt on riscv64.
pub const IRQ_BASE: u32 = 0;

/// Last usable interrupt on riscv64.
pub const IRQ_MAX: u32 = 1023;

/// AIA related devices
/// 0x0 ~ 0x0400_0000 (64 MiB) resides APLICs
pub const APLIC_START: u64 = 0;

/// 0x0400_0000 ~ 0x0800_0000 (64 MiB) resides IMSICs
pub const IMSIC_START: u64 = 0x0400_0000;

/// Below this address will reside the AIA, above this address will reside the MMIO devices.
#[cfg(not(feature = "efi"))]
pub const MAPPED_IO_START: u64 = 1 << 30; // 1 GB
#[cfg(feature = "efi")]
pub const MAPPED_IO_START: u64 = 0x0a00_0000;

#[cfg(feature = "efi")]
pub const SMBIOS_START: u64 = 0x4000_F000;

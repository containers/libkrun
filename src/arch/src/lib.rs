// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements platform specific functionality.
//! Supported platforms: x86_64 and aarch64.

use std::result;

#[derive(Default)]
pub struct ArchMemoryInfo {
    pub ram_last_addr: u64,
    pub shm_start_addr: u64,
    pub page_size: usize,
    pub initrd_addr: u64,
}

/// Module for aarch64 related functionality.
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    arch_memory_regions, configure_system, get_kernel_start, initrd_load_addr,
    layout::CMDLINE_MAX_SIZE, layout::IRQ_BASE, layout::IRQ_MAX, Error, MMIO_MEM_START,
};

/// Module for x86_64 related functionality.
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use crate::x86_64::{
    arch_memory_regions, configure_system, get_kernel_start, initrd_load_addr,
    layout::CMDLINE_MAX_SIZE, layout::IRQ_BASE, layout::IRQ_MAX, Error, BIOS_SIZE, BIOS_START,
    MMIO_MEM_START, RESET_VECTOR,
};

/// Type for returning public functions outcome.
pub type Result<T> = result::Result<T, Error>;

/// Type for passing information about the initrd in the guest memory.
pub struct InitrdConfig {
    /// Load address of initrd in guest memory
    pub address: vm_memory::GuestAddress,
    /// Size of initrd in guest memory
    pub size: usize,
}

/// Default (smallest) memory page size for the supported architectures.
pub const PAGE_SIZE: usize = 4096;

pub fn round_up(size: usize, align: usize) -> usize {
    let page_mask = align - 1;
    (size + page_mask) & !page_mask
}
pub fn round_down(size: usize, align: usize) -> usize {
    let page_mask = !(align - 1);
    size & page_mask
}

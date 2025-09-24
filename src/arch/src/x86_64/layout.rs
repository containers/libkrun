// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Magic addresses externally used to lay out x86_64 VMs.

/// Initial stack for the boot CPU.
pub const BOOT_STACK_POINTER: u64 = 0x8ff0;

/// Kernel command line start address.
pub const CMDLINE_START: u64 = 0x20000;
/// Kernel command line start address maximum size.
pub const CMDLINE_MAX_SIZE: usize = 0x10000;
/// Kernel command line static size on SEV.
pub const CMDLINE_SEV_SIZE: usize = 0x200;
/// Initrd start address on SEV.
pub const INITRD_SEV_START: u64 = 0xa00000;

/// Start of the high memory.
pub const HIMEM_START: u64 = 0x0010_0000; //1 MB.

// Typically, on x86 systems 16 IRQs are used (0-15).
/// First usable IRQ ID for virtio device interrupts on x86_64.
pub const IRQ_BASE: u32 = 5;
/// Last usable IRQ ID for virtio device interrupts on x86_64.
pub const IRQ_MAX: u32 = 15;

/// Address for the TSS setup.
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

/// The 'zero page', a.k.a linux kernel bootparams.
pub const ZERO_PAGE_START: u64 = 0x7000;

/// SNP: space for the initial LIDT
pub const SNP_LIDT_START: u64 = 0x0;
/// SNP: Secrets page.
pub const SNP_SECRETS_START: u64 = 0x5000;
/// SNP: CPUID page
pub const SNP_CPUID_START: u64 = 0x6000;
/// SNP: FW stack and initial page tables
pub const SNP_FWDATA_START: u64 = 0x8000;
pub const SNP_FWDATA_SIZE: usize = 0x7000;

// Where BIOS/VGA magic would live on a real PC.
pub const EBDA_START: u64 = 0x9fc00;

/// Where the PC register will point after a reset.
#[cfg(not(feature = "tdx"))]
pub const RESET_VECTOR: u64 = 0xfff0;
#[cfg(feature = "tdx")]
pub const RESET_VECTOR: u64 = 0xffff_fff0;
pub const RESET_VECTOR_SEV_AP: u64 = 0xfff3;

/// The address to load the firmware, if present.
pub const FIRMWARE_START: u64 = 0xffff_0000;

/// The size of the firmware.
pub const FIRMWARE_SIZE: u64 = 65536;

/// The start of the memory area reserved for MMIO devices.
pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
pub const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;

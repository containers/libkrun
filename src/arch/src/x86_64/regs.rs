// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem;

use super::gdt::{gdt_entry, segment_from_gdt, SegmentDescriptor};
use kvm_bindings::{kvm_fpu, kvm_regs, kvm_segment, kvm_sregs};
use kvm_ioctls::VcpuFd;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

// Initial pagetables.
const PML4_START: u64 = 0x9000;
const PDPTE_START: u64 = 0xa000;
const PDE_START: u64 = 0xb000;

/// Errors thrown while setting up x86_64 registers.
#[derive(Debug)]
pub enum Error {
    /// Failed to get SREGs for this CPU.
    GetStatusRegisters(kvm_ioctls::Error),
    /// Failed to set base registers for this CPU.
    SetBaseRegisters(kvm_ioctls::Error),
    /// Failed to configure the FPU.
    SetFPURegisters(kvm_ioctls::Error),
    /// Failed to set SREGs for this CPU.
    SetStatusRegisters(kvm_ioctls::Error),
    /// Writing the GDT to RAM failed.
    WriteGDT,
    /// Writing the IDT to RAM failed.
    WriteIDT,
    /// Writing PDPTE to RAM failed.
    WritePDPTEAddress,
    /// Writing PDE to RAM failed.
    WritePDEAddress,
    /// Writing PML4 to RAM failed.
    WritePML4Address,
}
type Result<T> = std::result::Result<T, Error>;

/// Configure Floating-Point Unit (FPU) registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_fpu(vcpu: &VcpuFd) -> Result<()> {
    let fpu: kvm_fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };

    vcpu.set_fpu(&fpu).map_err(Error::SetFPURegisters)
}

/// Configure base registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `boot_ip` - Starting instruction pointer.
pub fn setup_regs(vcpu: &VcpuFd, boot_ip: u64, id: u8) -> Result<()> {
    let regs: kvm_regs = if id == 0 || cfg!(not(feature = "tee")) {
        kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: boot_ip,
            // Frame pointer. It gets a snapshot of the stack pointer (rsp) so that when adjustments are
            // made to rsp (i.e. reserving space for local variables or pushing values on to the stack),
            // local variables and function parameters are still accessible from a constant offset from rbp.
            rsp: super::layout::BOOT_STACK_POINTER,
            // Starting stack pointer.
            rbp: super::layout::BOOT_STACK_POINTER,
            // Must point to zero page address per Linux ABI. This is x86_64 specific.
            rsi: super::layout::ZERO_PAGE_START,
            ..Default::default()
        }
    } else {
        kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: super::layout::RESET_VECTOR_SEV_AP,
            ..Default::default()
        }
    };

    vcpu.set_regs(&regs).map_err(Error::SetBaseRegisters)
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_sregs(mem: &GuestMemoryMmap, vcpu: &VcpuFd, id: u8) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(Error::GetStatusRegisters)?;

    if cfg!(not(feature = "tee")) {
        configure_segments_and_sregs(mem, &mut sregs)?;
        setup_page_tables(mem, &mut sregs)?; // TODO(dgreid) - Can this be done once per system instead
    } else if id != 0 {
        //sregs.cs.selector = 0x9100;
        //sregs.cs.base = 0x91000;
    }

    vcpu.set_sregs(&sregs).map_err(Error::SetStatusRegisters)
}

pub(crate) const BOOT_GDT_OFFSET: u64 = 0x500;
pub(crate) const BOOT_IDT_OFFSET: u64 = 0x520;

pub(crate) const BOOT_GDT_MAX: usize = 4;

pub(crate) const EFER_LMA: u64 = 0x400;
pub(crate) const EFER_LME: u64 = 0x100;

pub(crate) const X86_CR0_PE: u64 = 0x1;
pub(crate) const X86_CR0_PG: u64 = 0x8000_0000;
pub(crate) const X86_CR4_PAE: u64 = 0x20;

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemoryMmap) -> Result<()> {
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * mem::size_of::<u64>())
            .ok_or(Error::WriteGDT)?;
        guest_mem
            .write_obj(*entry, addr)
            .map_err(|_| Error::WriteGDT)?;
    }
    Ok(())
}

fn write_idt_value(val: u64, guest_mem: &GuestMemoryMmap) -> Result<()> {
    let boot_idt_addr = GuestAddress(BOOT_IDT_OFFSET);
    guest_mem
        .write_obj(val, boot_idt_addr)
        .map_err(|_| Error::WriteIDT)
}

/// Holds the agnostic segment/descriptor table configuration produced by
/// `compute_segments()`.
pub struct BootSegments {
    pub code_seg: SegmentDescriptor,
    pub data_seg: SegmentDescriptor,
    pub tss_seg: SegmentDescriptor,
    pub gdt_base: u64,
    pub gdt_limit: u16,
    pub idt_base: u64,
    pub idt_limit: u16,
}

/// Holds the page-table configuration produced by `compute_page_tables()`.
pub struct BootPageTables {
    pub cr3: u64,
    pub cr4_bits: u64,
    pub cr0_bits: u64,
}

/// Writes the GDT and IDT to guest memory and returns the agnostic boot
/// segment configuration.
pub fn compute_segments(mem: &GuestMemoryMmap) -> Result<BootSegments> {
    let gdt_table: [u64; BOOT_GDT_MAX] = [
        gdt_entry(0, 0, 0),            // NULL
        gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];

    // Write segments
    write_gdt_table(&gdt_table[..], mem)?;

    write_idt_value(0, mem)?;

    Ok(BootSegments {
        code_seg: segment_from_gdt(gdt_table[1], 1),
        data_seg: segment_from_gdt(gdt_table[2], 2),
        tss_seg: segment_from_gdt(gdt_table[3], 3),
        gdt_base: BOOT_GDT_OFFSET,
        gdt_limit: mem::size_of_val(&gdt_table) as u16 - 1,
        idt_base: BOOT_IDT_OFFSET,
        idt_limit: mem::size_of::<u64>() as u16 - 1,
    })
}

/// Writes the identity-mapped page tables to guest memory and returns the
/// agnostic page-table configuration.
pub fn compute_page_tables(mem: &GuestMemoryMmap) -> Result<BootPageTables> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = GuestAddress(PML4_START);
    let boot_pdpte_addr = GuestAddress(PDPTE_START);
    let boot_pde_addr = GuestAddress(PDE_START);

    // Entry covering VA [0..512GB)
    mem.write_obj(boot_pdpte_addr.raw_value() | 0x03, boot_pml4_addr)
        .map_err(|_| Error::WritePML4Address)?;

    // Entry covering VA [0..1GB)
    mem.write_obj(boot_pde_addr.raw_value() | 0x03, boot_pdpte_addr)
        .map_err(|_| Error::WritePDPTEAddress)?;
    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_obj((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
            .map_err(|_| Error::WritePDEAddress)?;
    }

    Ok(BootPageTables {
        cr3: boot_pml4_addr.raw_value(),
        cr4_bits: X86_CR4_PAE,
        cr0_bits: X86_CR0_PG,
    })
}

fn kvm_segment_from(seg: &SegmentDescriptor) -> kvm_segment {
    kvm_segment {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector,
        type_: seg.type_,
        present: seg.present,
        dpl: seg.dpl,
        db: seg.db,
        s: seg.s,
        l: seg.l,
        g: seg.g,
        avl: seg.avl,
        padding: 0,
        unusable: seg.unusable,
    }
}

fn configure_segments_and_sregs(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    let segs = compute_segments(mem)?;

    let code_seg = kvm_segment_from(&segs.code_seg);
    let data_seg = kvm_segment_from(&segs.data_seg);
    let tss_seg = kvm_segment_from(&segs.tss_seg);

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    sregs.gdt.base = segs.gdt_base;
    sregs.gdt.limit = segs.gdt_limit;
    sregs.idt.base = segs.idt_base;
    sregs.idt.limit = segs.idt_limit;

    /* 64-bit protected mode */
    sregs.cr0 |= X86_CR0_PE;
    sregs.efer |= EFER_LME | EFER_LMA;

    Ok(())
}

fn setup_page_tables(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    let pt = compute_page_tables(mem)?;
    sregs.cr3 = pt.cr3;
    sregs.cr4 |= pt.cr4_bits;
    sregs.cr0 |= pt.cr0_bits;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_ioctls::Kvm;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn read_u64(gm: &GuestMemoryMmap, offset: u64) -> u64 {
        let read_addr = GuestAddress(offset);
        gm.read_obj(read_addr).unwrap()
    }

    fn validate_segments_and_sregs(gm: &GuestMemoryMmap, sregs: &kvm_sregs) {
        assert_eq!(0x0, read_u64(gm, BOOT_GDT_OFFSET));
        assert_eq!(0xaf_9b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 8));
        assert_eq!(0xcf_9300_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 16));
        assert_eq!(0x8f_8b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 24));
        assert_eq!(0x0, read_u64(gm, BOOT_IDT_OFFSET));

        assert_eq!(0, sregs.cs.base);
        assert_eq!(0xfffff, sregs.ds.limit);
        assert_eq!(0x10, sregs.es.selector);
        assert_eq!(1, sregs.fs.present);
        assert_eq!(1, sregs.gs.g);
        assert_eq!(0, sregs.ss.avl);
        assert_eq!(0, sregs.tr.base);
        assert_eq!(0xfffff, sregs.tr.limit);
        assert_eq!(0, sregs.tr.avl);
        assert!(sregs.cr0 & X86_CR0_PE != 0);
        assert!(sregs.efer & EFER_LME != 0 && sregs.efer & EFER_LMA != 0);
    }

    #[test]
    fn test_configure_segments_and_sregs() {
        let mut sregs: kvm_sregs = Default::default();
        let gm = create_guest_mem();
        configure_segments_and_sregs(&gm, &mut sregs).unwrap();

        validate_segments_and_sregs(&gm, &sregs);
    }

    fn validate_page_tables(gm: &GuestMemoryMmap, cr3: u64, cr4: u64, cr0: u64) {
        assert_eq!(0xa003, read_u64(gm, PML4_START));
        assert_eq!(0xb003, read_u64(gm, PDPTE_START));
        for i in 0..512 {
            assert_eq!((i << 21) + 0x83u64, read_u64(gm, PDE_START + (i * 8)));
        }

        assert_eq!(PML4_START, cr3);
        assert!(cr4 & X86_CR4_PAE != 0);
        assert!(cr0 & X86_CR0_PG != 0);
    }

    #[test]
    fn test_compute_page_tables() {
        let gm = create_guest_mem();
        let page_tables = compute_page_tables(&gm).unwrap();
        validate_page_tables(
            &gm,
            page_tables.cr3,
            page_tables.cr4_bits,
            page_tables.cr0_bits,
        );
    }

    #[test]
    fn test_compute_segments() {
        let gm = create_guest_mem();
        let segs = compute_segments(&gm).unwrap();
        assert_eq!(0, segs.code_seg.base);
        assert_eq!(0xfffff, segs.data_seg.limit);
        assert_eq!(0x10, segs.data_seg.selector);
    }

    #[test]
    fn test_setup_fpu() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_fpu(&vcpu).unwrap();

        let expected_fpu: kvm_fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        let actual_fpu: kvm_fpu = vcpu.get_fpu().unwrap();
        // TODO: auto-generate kvm related structures with PartialEq on.
        assert_eq!(expected_fpu.fcw, actual_fpu.fcw);
        // Setting the mxcsr register from kvm_fpu inside setup_fpu does not influence anything.
        // See 'kvm_arch_vcpu_ioctl_set_fpu' from arch/x86/kvm/x86.c.
        // The mxcsr will stay 0 and the assert below fails. Decide whether or not we should
        // remove it at all.
        // assert!(expected_fpu.mxcsr == actual_fpu.mxcsr);
    }

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let expected_regs: kvm_regs = kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: 1,
            rsp: super::super::layout::BOOT_STACK_POINTER,
            rbp: super::super::layout::BOOT_STACK_POINTER,
            rsi: super::super::layout::ZERO_PAGE_START,
            ..Default::default()
        };

        setup_regs(&vcpu, expected_regs.rip, 1).unwrap();

        let actual_regs: kvm_regs = vcpu.get_regs().unwrap();
        assert_eq!(actual_regs, expected_regs);
    }

    #[test]
    fn test_setup_sregs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let gm = create_guest_mem();

        assert!(vcpu.set_sregs(&Default::default()).is_ok());
        setup_sregs(&gm, &vcpu, 1).unwrap();

        let mut sregs: kvm_sregs = vcpu.get_sregs().unwrap();
        // for AMD KVM_GET_SREGS returns g = 0 for each kvm_segment.
        // We set it to 1, otherwise the test will fail.
        sregs.gs.g = 1;

        validate_segments_and_sregs(&gm, &sregs);
        validate_page_tables(&gm, sregs.cr3, sregs.cr4, sregs.cr0);
    }
}

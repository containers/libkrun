// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

#[allow(non_camel_case_types)]
#[allow(improper_ctypes)]
#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(deref_nullptr)]
pub mod bindings;

use bindings::*;

#[cfg(target_arch = "aarch64")]
use std::arch::asm;

use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use arch::aarch64::sysreg::{icc_reg_name, SYSREG_MASK};
use crossbeam_channel::Sender;
use log::debug;

extern "C" {
    pub fn mach_absolute_time() -> u64;
}

const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;

const TMR_CTL_ENABLE: u64 = 1 << 0;
const TMR_CTL_IMASK: u64 = 1 << 1;
const TMR_CTL_ISTATUS: u64 = 1 << 2;

const PSR_MODE_EL1H: u64 = 0x0000_0005;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
const PSTATE_FAULT_BITS_64: u64 = PSR_MODE_EL1H | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

const EC_WFX_TRAP: u64 = 0x1;
const EC_AA64_HVC: u64 = 0x16;
const EC_AA64_SMC: u64 = 0x17;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
const EC_SYSTEMREGISTERTRAP: u64 = 0x18;
const EC_DATAABORT: u64 = 0x24;
const EC_AA64_BKPT: u64 = 0x3c;

#[derive(Debug)]
pub enum Error {
    FindSymbol(libloading::Error),
    MemoryMap,
    MemoryUnmap,
    VcpuCreate,
    VcpuInitialRegisters,
    VcpuReadRegister,
    VcpuReadSystemRegister,
    VcpuRequestExit,
    VcpuRun,
    VcpuSetPendingIrq,
    VcpuSetRegister,
    VcpuSetSystemRegister(u16, u64),
    VcpuSetVtimerMask,
    VmCreate,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            FindSymbol(ref err) => write!(f, "Couldn't find symbol in HVF library: {}", err),
            MemoryMap => write!(f, "Error registering memory region in HVF"),
            MemoryUnmap => write!(f, "Error unregistering memory region in HVF"),
            VcpuCreate => write!(f, "Error creating HVF vCPU instance"),
            VcpuInitialRegisters => write!(f, "Error setting up initial HVF vCPU registers"),
            VcpuReadRegister => write!(f, "Error reading HVF vCPU register"),
            VcpuReadSystemRegister => write!(f, "Error reading HVF vCPU system register"),
            VcpuRequestExit => write!(f, "Error requesting HVF vCPU exit"),
            VcpuRun => write!(f, "Error running HVF vCPU"),
            VcpuSetPendingIrq => write!(f, "Error setting HVF vCPU pending irq"),
            VcpuSetRegister => write!(f, "Error setting HVF vCPU register"),
            VcpuSetSystemRegister(reg, val) => write!(
                f,
                "Error setting HVF vCPU system register 0x{:#x} to 0x{:#x}",
                reg, val
            ),
            VcpuSetVtimerMask => write!(f, "Error setting HVF vCPU vtimer mask"),
            VmCreate => write!(f, "Error creating HVF VM instance"),
        }
    }
}

/// Messages for requesting memory maps/unmaps.
pub enum MemoryMapping {
    AddMapping(Sender<bool>, u64, u64, u64),
    RemoveMapping(Sender<bool>, u64, u64),
}

pub enum InterruptType {
    Irq,
    Fiq,
}

pub trait Vcpus {
    fn set_vtimer_irq(&self, vcpuid: u64);
    fn should_wait(&self, vcpuid: u64) -> bool;
    fn has_pending_irq(&self, vcpuid: u64) -> bool;
    fn get_pending_irq(&self, vcpuid: u64) -> u32;
    fn handle_sysreg_read(&self, vcpuid: u64, reg: u32) -> Option<u64>;
    fn handle_sysreg_write(&self, vcpuid: u64, reg: u32, val: u64) -> bool;
}

pub fn vcpu_request_exit(vcpuid: u64) -> Result<(), Error> {
    let mut vcpu: u64 = vcpuid;
    let ret = unsafe { hv_vcpus_exit(&mut vcpu, 1) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuRequestExit)
    } else {
        Ok(())
    }
}

pub fn vcpu_set_pending_irq(
    vcpuid: u64,
    irq_type: InterruptType,
    pending: bool,
) -> Result<(), Error> {
    let _type = match irq_type {
        InterruptType::Irq => hv_interrupt_type_t_HV_INTERRUPT_TYPE_IRQ,
        InterruptType::Fiq => hv_interrupt_type_t_HV_INTERRUPT_TYPE_FIQ,
    };

    let ret = unsafe { hv_vcpu_set_pending_interrupt(vcpuid, _type, pending) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuSetPendingIrq)
    } else {
        Ok(())
    }
}

pub fn vcpu_set_vtimer_mask(vcpuid: u64, masked: bool) -> Result<(), Error> {
    let ret = unsafe { hv_vcpu_set_vtimer_mask(vcpuid, masked) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuSetVtimerMask)
    } else {
        Ok(())
    }
}

pub struct HvfVm {}

impl HvfVm {
    pub fn new() -> Result<Self, Error> {
        let ret = unsafe { hv_vm_create(std::ptr::null_mut()) };

        if ret != HV_SUCCESS {
            Err(Error::VmCreate)
        } else {
            Ok(Self {})
        }
    }

    pub fn map_memory(
        &self,
        host_start_addr: u64,
        guest_start_addr: u64,
        size: u64,
    ) -> Result<(), Error> {
        let ret = unsafe {
            hv_vm_map(
                host_start_addr as *mut core::ffi::c_void,
                guest_start_addr,
                size.try_into().unwrap(),
                (HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC).into(),
            )
        };
        if ret != HV_SUCCESS {
            Err(Error::MemoryMap)
        } else {
            Ok(())
        }
    }

    pub fn unmap_memory(&self, guest_start_addr: u64, size: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vm_unmap(guest_start_addr, size.try_into().unwrap()) };
        if ret != HV_SUCCESS {
            Err(Error::MemoryUnmap)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub enum VcpuExit<'a> {
    Breakpoint,
    Canceled,
    CpuOn(u64, u64, u64),
    HypervisorCall,
    MmioRead(u64, &'a mut [u8]),
    MmioWrite(u64, &'a [u8]),
    SecureMonitorCall,
    Shutdown,
    SystemRegister,
    VtimerActivated,
    WaitForEvent,
    WaitForEventExpired,
    WaitForEventTimeout(Duration),
}

struct MmioRead {
    addr: u64,
    len: usize,
    srt: u32,
}

pub struct HvfVcpu<'a> {
    vcpuid: hv_vcpu_t,
    vcpu_exit: &'a hv_vcpu_exit_t,
    cntfrq: u64,
    mmio_buf: [u8; 8],
    pending_mmio_read: Option<MmioRead>,
    pending_advance_pc: bool,
    vtimer_masked: bool,
}

impl HvfVcpu<'_> {
    pub fn new(mpidr: u64) -> Result<Self, Error> {
        let mut vcpuid: hv_vcpu_t = 0;
        let vcpu_exit_ptr: *mut hv_vcpu_exit_t = std::ptr::null_mut();

        #[cfg(target_arch = "aarch64")]
        let cntfrq = {
            let cntfrq: u64;
            unsafe { asm!("mrs {}, cntfrq_el0", out(reg) cntfrq) };
            cntfrq
        };
        #[cfg(target_arch = "x86_64")]
        let cntfrq = 0u64;

        let ret = unsafe {
            hv_vcpu_create(
                &mut vcpuid,
                &vcpu_exit_ptr as *const _ as *mut *mut _,
                std::ptr::null_mut(),
            )
        };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuCreate);
        }

        // We write vcpuid to Aff1 as otherwise it won't match the redistributor ID
        // when using HVF in-kernel GICv3.
        let ret = unsafe { hv_vcpu_set_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_MPIDR_EL1, mpidr) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuCreate);
        }

        let vcpu_exit: &hv_vcpu_exit_t = unsafe { vcpu_exit_ptr.as_mut().unwrap() };

        Ok(Self {
            vcpuid,
            vcpu_exit,
            cntfrq,
            mmio_buf: [0; 8],
            pending_mmio_read: None,
            pending_advance_pc: false,
            vtimer_masked: false,
        })
    }

    pub fn set_initial_state(&self, entry_addr: u64, fdt_addr: u64) -> Result<(), Error> {
        let ret =
            unsafe { hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_CPSR, PSTATE_FAULT_BITS_64) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuInitialRegisters);
        }

        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_PC, entry_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuInitialRegisters);
        }

        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_X0, fdt_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuInitialRegisters);
        }

        Ok(())
    }

    pub fn id(&self) -> u64 {
        self.vcpuid
    }

    fn read_reg(&self, reg: u32) -> Result<u64, Error> {
        let val: u64 = 0;
        let ret = unsafe { hv_vcpu_get_reg(self.vcpuid, reg, &val as *const _ as *mut _) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuReadRegister)
        } else {
            Ok(val)
        }
    }

    pub fn write_reg(&self, rt: u32, val: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, rt, val) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuSetRegister)
        } else {
            Ok(())
        }
    }

    fn read_sys_reg(&self, reg: u16) -> Result<u64, Error> {
        let val: u64 = 0;
        let ret = unsafe { hv_vcpu_get_sys_reg(self.vcpuid, reg, &val as *const _ as *mut _) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuReadSystemRegister)
        } else {
            Ok(val)
        }
    }

    fn hvf_sync_vtimer(&mut self, vcpu_list: Arc<dyn Vcpus>) {
        if !self.vtimer_masked {
            return;
        }

        let ctl = self
            .read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0)
            .unwrap();
        let irq_state = (ctl & (TMR_CTL_ENABLE | TMR_CTL_IMASK | TMR_CTL_ISTATUS))
            == (TMR_CTL_ENABLE | TMR_CTL_ISTATUS);
        vcpu_list.set_vtimer_irq(self.vcpuid);
        if !irq_state {
            vcpu_set_vtimer_mask(self.vcpuid, false).unwrap();
            self.vtimer_masked = false;
        }
    }

    pub fn run(&mut self, vcpu_list: Arc<dyn Vcpus>) -> Result<VcpuExit, Error> {
        let pending_irq = vcpu_list.has_pending_irq(self.vcpuid);

        if let Some(mmio_read) = self.pending_mmio_read.take() {
            if mmio_read.srt < 31 {
                let val = match mmio_read.len {
                    1 => u8::from_le_bytes(self.mmio_buf[0..1].try_into().unwrap()) as u64,
                    2 => u16::from_le_bytes(self.mmio_buf[0..2].try_into().unwrap()) as u64,
                    4 => u32::from_le_bytes(self.mmio_buf[0..4].try_into().unwrap()) as u64,
                    8 => u64::from_le_bytes(self.mmio_buf[0..8].try_into().unwrap()),
                    _ => panic!(
                        "unsupported mmio pa={} len={}",
                        mmio_read.addr, mmio_read.len
                    ),
                };

                self.write_reg(mmio_read.srt, val)?;
            }
        }

        if self.pending_advance_pc {
            let pc = self.read_reg(hv_reg_t_HV_REG_PC)?;
            self.write_reg(hv_reg_t_HV_REG_PC, pc + 4)?;
            self.pending_advance_pc = false;
        }

        if pending_irq {
            vcpu_set_pending_irq(self.vcpuid, InterruptType::Irq, true)?;
        }

        let ret = unsafe { hv_vcpu_run(self.vcpuid) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuRun);
        }

        match self.vcpu_exit.reason {
            HV_EXIT_REASON_EXCEPTION => { /* This is the main one, handle below. */ }
            HV_EXIT_REASON_VTIMER_ACTIVATED => {
                self.vtimer_masked = true;
                return Ok(VcpuExit::VtimerActivated);
            }
            HV_EXIT_REASON_CANCELED => return Ok(VcpuExit::Canceled),
            _ => {
                let pc = self.read_reg(hv_reg_t_HV_REG_PC)?;
                panic!(
                    "unexpected exit reason: vcpuid={} 0x{:x} at pc=0x{:x}",
                    self.id(),
                    self.vcpu_exit.reason,
                    pc
                );
            }
        }

        self.hvf_sync_vtimer(vcpu_list.clone());

        let syndrome = self.vcpu_exit.exception.syndrome;
        let ec = (syndrome >> 26) & 0x3f;
        match ec {
            EC_AA64_BKPT => {
                debug!("vcpu[{}]: BRK exit", self.vcpuid);
                Ok(VcpuExit::Breakpoint)
            }
            EC_DATAABORT => {
                let isv: bool = (syndrome & (1 << 24)) != 0;
                let iswrite: bool = ((syndrome >> 6) & 1) != 0;
                let s1ptw: bool = ((syndrome >> 7) & 1) != 0;
                let sas: u32 = ((syndrome >> 22) & 3) as u32;
                let len: usize = (1 << sas) as usize;
                let srt: u32 = ((syndrome >> 16) & 0x1f) as u32;
                let cm: u32 = ((syndrome >> 8) & 0x1) as u32;

                debug!(
                    "EC_DATAABORT {} {} {} {} {} {} {} {}",
                    syndrome, isv as u8, iswrite as u8, s1ptw as u8, sas, len, srt, cm
                );

                let pa = self.vcpu_exit.exception.physical_address;
                self.pending_advance_pc = true;

                if iswrite {
                    let val = if srt < 31 {
                        self.read_reg(hv_reg_t_HV_REG_X0 + srt)?
                    } else {
                        0
                    };

                    match len {
                        1 => self.mmio_buf[0..1].copy_from_slice(&(val as u8).to_le_bytes()),
                        4 => self.mmio_buf[0..4].copy_from_slice(&(val as u32).to_le_bytes()),
                        8 => self.mmio_buf[0..8].copy_from_slice(&val.to_le_bytes()),
                        _ => panic!("unsupported mmio len={len}"),
                    };

                    Ok(VcpuExit::MmioWrite(pa, &self.mmio_buf[0..len]))
                } else {
                    self.pending_mmio_read = Some(MmioRead { addr: pa, srt, len });
                    Ok(VcpuExit::MmioRead(pa, &mut self.mmio_buf[0..len]))
                }
            }
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            EC_SYSTEMREGISTERTRAP => {
                let isread: bool = (syndrome & 1) != 0;
                let rt: u32 = ((syndrome >> 5) & 0x1f) as u32;
                let reg: u32 = syndrome as u32 & SYSREG_MASK;
                debug!(
                    "EC_SYSTEMREGISTERTRAP isread={}, syndrome={}, rt={}, reg={}, reg_name={}",
                    isread as u32,
                    syndrome,
                    rt,
                    reg,
                    icc_reg_name(reg).unwrap_or("non-ICC reg")
                );

                self.pending_advance_pc = true;

                if isread {
                    assert!(rt < 32);

                    // See https://developer.arm.com/documentation/dui0801/l/Overview-of-AArch64-state/Registers-in-AArch64-state
                    if rt == 31 {
                        return Ok(VcpuExit::SystemRegister);
                    }

                    match vcpu_list.handle_sysreg_read(self.vcpuid, reg) {
                        Some(val) => {
                            self.write_reg(rt, val)?;
                            Ok(VcpuExit::SystemRegister)
                        }
                        None => panic!(
                            "UNKNOWN rt={}, reg={} name={}",
                            rt,
                            reg,
                            icc_reg_name(reg).unwrap()
                        ),
                    }
                } else {
                    assert!(rt < 32);

                    // See https://developer.arm.com/documentation/dui0801/l/Overview-of-AArch64-state/Registers-in-AArch64-state
                    let val = if rt == 31 { 0u64 } else { self.read_reg(rt)? };

                    if vcpu_list.handle_sysreg_write(self.vcpuid, reg, val) {
                        Ok(VcpuExit::SystemRegister)
                    } else {
                        panic!(
                            "unexpected write: {} name={}",
                            reg,
                            icc_reg_name(reg).unwrap_or("non-ICC reg")
                        )
                    }
                }
            }
            EC_WFX_TRAP => {
                let ctl = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0)?;

                self.pending_advance_pc = true;
                if ((ctl & 1) == 0) || (ctl & 2) != 0 {
                    return Ok(VcpuExit::WaitForEvent);
                }

                // Also CNTV_CVAL & CNTV_CVAL_EL0
                let cval = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0)?;
                let now = unsafe { mach_absolute_time() };
                if now > cval {
                    return Ok(VcpuExit::WaitForEventExpired);
                }

                let timeout = Duration::from_nanos((cval - now) * (1_000_000_000 / self.cntfrq));
                Ok(VcpuExit::WaitForEventTimeout(timeout))
            }
            EC_AA64_HVC => {
                match self.read_reg(hv_reg_t_HV_REG_X0)? {
                    0x8400_0000 /* QEMU_PSCI_0_2_FN_PSCI_VERSION */ => {
                        self.write_reg(hv_reg_t_HV_REG_X0, 2)?;
                        Ok(VcpuExit::HypervisorCall)
                    },
                    0x8400_0006 /* QEMU_PSCI_0_2_FN_MIGRATE_INFO_TYPE */ => {
                        self.write_reg(hv_reg_t_HV_REG_X0, 2)?;
                        Ok(VcpuExit::HypervisorCall)
                    },
                    0x8400_0008 /* QEMU_PSCI_0_2_FN_SYSTEM_OFF */ => {
                        Ok(VcpuExit::Shutdown)
                    },
                    0x8400_0009 /* QEMU_PSCI_0_2_FN_SYSTEM_RESET */ => {
                        Ok(VcpuExit::Shutdown)
                    },
                    0xc400_0003 /* QEMU_PSCI_0_2_FN64_CPU_ON */ => {
                        let mpidr = self.read_reg(hv_reg_t_HV_REG_X1)?;
                        let entry = self.read_reg(hv_reg_t_HV_REG_X2)?;
                        let context_id = self.read_reg(hv_reg_t_HV_REG_X3)?;
                        self.write_reg(hv_reg_t_HV_REG_X0, 0)?;
                        Ok(VcpuExit::CpuOn(mpidr, entry, context_id))
                    }
                    val => panic!("Unexpected val={}", val)
                }
            }
            EC_AA64_SMC => {
                self.pending_advance_pc = true;
                Ok(VcpuExit::SecureMonitorCall)
            }
            _ => panic!("unexpected exception: 0x{ec:x}"),
        }
    }
}

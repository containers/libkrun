// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

#[allow(non_camel_case_types)]
#[allow(improper_ctypes)]
#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(deref_nullptr)]
mod bindings;
use bindings::*;

use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::time::Duration;

use crossbeam_channel::Sender;
use log::debug;

extern "C" {
    pub fn mach_absolute_time() -> u64;
}

const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;

const PSR_MODE_EL1H: u64 = 0x0000_0005;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
const PSTATE_FAULT_BITS_64: u64 = PSR_MODE_EL1H | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

const EC_WFX_TRAP: u64 = 0x1;
const EC_AA64_HVC: u64 = 0x16;
const EC_AA64_SMC: u64 = 0x17;
const EC_SYSTEMREGISTERTRAP: u64 = 0x18;
const EC_DATAABORT: u64 = 0x24;
const EC_AA64_BKPT: u64 = 0x3c;

macro_rules! arm64_sys_reg {
    ($name: tt, $op0: tt, $op1: tt, $op2: tt, $crn: tt, $crm: tt) => {
        const $name: u64 = ($op0 as u64) << 20
            | ($op2 as u64) << 17
            | ($op1 as u64) << 14
            | ($crn as u64) << 10
            | ($crm as u64) << 1;
    };
}

arm64_sys_reg!(SYSREG_MASK, 0x3, 0x7, 0x7, 0xf, 0xf);

/*
arm64_sys_reg!(SYSREG_CNTPCT_EL0, 3, 3, 1, 14, 0);
arm64_sys_reg!(SYSREG_PMCCNTR_EL0, 3, 3, 0, 9, 13);
arm64_sys_reg!(SYSREG_ICC_AP0R0_EL1, 3, 0, 4, 12, 8);
arm64_sys_reg!(SYSREG_ICC_AP0R1_EL1, 3, 0, 5, 12, 8);
arm64_sys_reg!(SYSREG_ICC_AP0R2_EL1, 3, 0, 6, 12, 8);
arm64_sys_reg!(SYSREG_ICC_AP0R3_EL1, 3, 0, 7, 12, 8);
arm64_sys_reg!(SYSREG_ICC_AP1R0_EL1, 3, 0, 0, 12, 9);
arm64_sys_reg!(SYSREG_ICC_AP1R1_EL1, 3, 0, 1, 12, 9);
arm64_sys_reg!(SYSREG_ICC_AP1R2_EL1, 3, 0, 2, 12, 9);
arm64_sys_reg!(SYSREG_ICC_AP1R3_EL1, 3, 0, 3, 12, 9);
arm64_sys_reg!(SYSREG_ICC_ASGI1R_EL1, 3, 0, 6, 12, 11);
arm64_sys_reg!(SYSREG_ICC_BPR0_EL1, 3, 0, 3, 12, 8);
arm64_sys_reg!(SYSREG_ICC_BPR1_EL1, 3, 0, 3, 12, 12);
arm64_sys_reg!(SYSREG_ICC_CTLR_EL1, 3, 0, 4, 12, 12);
arm64_sys_reg!(SYSREG_ICC_DIR_EL1, 3, 0, 1, 12, 11);
arm64_sys_reg!(SYSREG_ICC_EOIR0_EL1, 3, 0, 1, 12, 8);
arm64_sys_reg!(SYSREG_ICC_EOIR1_EL1, 3, 0, 1, 12, 12);
arm64_sys_reg!(SYSREG_ICC_HPPIR0_EL1, 3, 0, 2, 12, 8);
arm64_sys_reg!(SYSREG_ICC_HPPIR1_EL1, 3, 0, 2, 12, 12);
arm64_sys_reg!(SYSREG_ICC_IAR0_EL1, 3, 0, 0, 12, 8);
arm64_sys_reg!(SYSREG_ICC_IAR1_EL1, 3, 0, 0, 12, 12);
arm64_sys_reg!(SYSREG_ICC_IGRPEN0_EL1, 3, 0, 6, 12, 12);
arm64_sys_reg!(SYSREG_ICC_IGRPEN1_EL1, 3, 0, 7, 12, 12);
arm64_sys_reg!(SYSREG_ICC_PMR_EL1, 3, 0, 0, 4, 6);
arm64_sys_reg!(SYSREG_ICC_RPR_EL1, 3, 0, 3, 12, 11);
arm64_sys_reg!(SYSREG_ICC_SGI0R_EL1, 3, 0, 7, 12, 11);
arm64_sys_reg!(SYSREG_ICC_SGI1R_EL1, 3, 0, 5, 12, 11);
arm64_sys_reg!(SYSREG_ICC_SRE_EL1, 3, 0, 5, 12, 12);
*/

#[derive(Clone, Debug)]
pub enum Error {
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
    VcpuSetSystemRegister,
    VcpuSetVtimerMask,
    VmCreate,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
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
            VcpuSetSystemRegister => write!(f, "Error setting HVF vCPU system register"),
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
                size,
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
        let ret = unsafe { hv_vm_unmap(guest_start_addr, size) };
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
}

impl<'a> HvfVcpu<'a> {
    pub fn new() -> Result<Self, Error> {
        let mut vcpuid: hv_vcpu_t = 0;
        let vcpu_exit_ptr: *mut hv_vcpu_exit_t = std::ptr::null_mut();
        let cntfrq: u64 = 24000000;

        // TODO - Once inline assembly is stabilized in Rust, re-enable this:
        //unsafe { asm!("mrs {}, cntfrq_el0", out(reg) cntfrq) };

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

        let vcpu_exit: &hv_vcpu_exit_t = unsafe { vcpu_exit_ptr.as_mut().unwrap() };

        Ok(Self {
            vcpuid,
            vcpu_exit,
            cntfrq,
            mmio_buf: [0; 8],
            pending_mmio_read: None,
            pending_advance_pc: false,
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

    fn write_reg(&self, reg: u32, val: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, reg, val) };
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

    #[allow(dead_code)]
    fn write_sys_reg(&self, reg: u16, val: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vcpu_set_sys_reg(self.vcpuid, reg, val) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuSetSystemRegister)
        } else {
            Ok(())
        }
    }

    pub fn run(&mut self, pending_irq: bool) -> Result<VcpuExit, Error> {
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

                self.write_reg(hv_reg_t_HV_REG_X0 + mmio_read.srt, val)?;
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
            HV_EXIT_REASON_CANCELED => Ok(VcpuExit::Canceled),
            HV_EXIT_REASON_EXCEPTION => {
                let syndrome = self.vcpu_exit.exception.syndrome;
                let ec = (syndrome >> 26) & 0x3f;

                match ec {
                    EC_AA64_HVC => {
                        let val = self.read_reg(hv_reg_t_HV_REG_X0)?;

                        debug!("HVC: 0x{:x}", val);
                        let ret = match val {
                            0x8400_0000 => Some(2),
                            0x8400_0006 => Some(2),
                            0x8400_0009 => return Ok(VcpuExit::Shutdown),
                            0xc400_0003 => {
                                let mpidr = self.read_reg(hv_reg_t_HV_REG_X1)?;
                                let entry = self.read_reg(hv_reg_t_HV_REG_X2)?;
                                let context_id = self.read_reg(hv_reg_t_HV_REG_X3)?;
                                self.write_reg(hv_reg_t_HV_REG_X0, 0)?;
                                return Ok(VcpuExit::CpuOn(mpidr, entry, context_id));
                            }
                            _ => {
                                debug!("HVC call unhandled");
                                None
                            }
                        };

                        if let Some(ret) = ret {
                            self.write_reg(hv_reg_t_HV_REG_X0, ret)?;
                        }

                        Ok(VcpuExit::HypervisorCall)
                    }
                    EC_AA64_SMC => {
                        debug!("SMC exit");

                        self.pending_advance_pc = true;
                        Ok(VcpuExit::SecureMonitorCall)
                    }
                    EC_SYSTEMREGISTERTRAP => {
                        let isread: bool = (syndrome & 1) != 0;
                        let rt: u32 = ((syndrome >> 5) & 0x1f) as u32;
                        let reg: u64 = syndrome & SYSREG_MASK;

                        debug!("sysreg operation reg={} (op0={} op1={} op2={} crn={} crm={}) isread={:?}",
                               reg, (reg >> 20) & 0x3,
                               (reg >> 14) & 0x7, (reg >> 17) & 0x7,
                               (reg >> 10) & 0xf, (reg >> 1) & 0xf,
                               isread);

                        if isread && rt < 31 {
                            self.write_reg(rt, 0)?;
                        }

                        self.pending_advance_pc = true;
                        Ok(VcpuExit::SystemRegister)
                    }
                    EC_DATAABORT => {
                        let isv: bool = (syndrome & (1 << 24)) != 0;
                        let iswrite: bool = ((syndrome >> 6) & 1) != 0;
                        let s1ptw: bool = ((syndrome >> 7) & 1) != 0;
                        let sas: u32 = (syndrome as u32 >> 22) & 3;
                        let len: usize = (1 << sas) as usize;
                        let srt: u32 = (syndrome as u32 >> 16) & 0x1f;

                        debug!("data abort: va={:x}, pa={:x}, isv={}, iswrite={:?}, s1ptrw={}, len={}, srt={}",
                               self.vcpu_exit.exception.virtual_address,
                               self.vcpu_exit.exception.physical_address,
                               isv, iswrite, s1ptw, len, srt);

                        let pa = self.vcpu_exit.exception.physical_address;
                        self.pending_advance_pc = true;

                        if iswrite {
                            let val = if srt < 31 {
                                self.read_reg(hv_reg_t_HV_REG_X0 + srt)?
                            } else {
                                0u64
                            };

                            match len {
                                1 => {
                                    self.mmio_buf[0..1].copy_from_slice(&(val as u8).to_le_bytes())
                                }
                                4 => {
                                    self.mmio_buf[0..4].copy_from_slice(&(val as u32).to_le_bytes())
                                }
                                8 => self.mmio_buf[0..8].copy_from_slice(&(val).to_le_bytes()),
                                _ => panic!("unsupported mmio len={len}"),
                            };

                            Ok(VcpuExit::MmioWrite(pa, &self.mmio_buf[0..len]))
                        } else {
                            self.pending_mmio_read = Some(MmioRead { addr: pa, srt, len });
                            Ok(VcpuExit::MmioRead(pa, &mut self.mmio_buf[0..len]))
                        }
                    }
                    EC_AA64_BKPT => {
                        debug!("BRK exit");
                        Ok(VcpuExit::Breakpoint)
                    }
                    EC_WFX_TRAP => {
                        debug!("WFX exit");
                        let ctl = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0)?;

                        self.pending_advance_pc = true;
                        if ((ctl & 1) == 0) || (ctl & 2) != 0 {
                            Ok(VcpuExit::WaitForEvent)
                        } else {
                            let cval = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0)?;
                            let now = unsafe { mach_absolute_time() };

                            if now > cval {
                                Ok(VcpuExit::WaitForEventExpired)
                            } else {
                                let timeout = Duration::from_nanos(
                                    (cval - now) * (1_000_000_000 / self.cntfrq),
                                );
                                Ok(VcpuExit::WaitForEventTimeout(timeout))
                            }
                        }
                    }
                    _ => panic!("unexpected exception: 0x{ec:x}"),
                }
            }
            HV_EXIT_REASON_VTIMER_ACTIVATED => Ok(VcpuExit::VtimerActivated),
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
    }
}

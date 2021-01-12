// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::convert::TryInto;
use std::sync::mpsc::Sender;

use arch::aarch64::gicv2::GICv2;
use arch::aarch64::layout::GTIMER_VIRT;
use hvf::vcpu_set_vtimer_mask;

use crate::bus::BusDevice;

const IRQ_NUM: u32 = 64;

enum VcpuStatus {
    Running,
    Waiting,
}

struct VcpuInfo {
    status: VcpuStatus,
    pending_irqs: VecDeque<u32>,
    wfe_sender: Sender<u32>,
}

pub struct Gic {
    cpu_size: u64,
    ctlr: u32,
    irq_cfg: [u32; IRQ_NUM as usize],
    vcpus: BTreeMap<u64, VcpuInfo>,
    irq_enabled: [bool; IRQ_NUM as usize],
    vtimer_irq: u32,
}

impl Gic {
    pub fn new() -> Self {
        Self {
            cpu_size: GICv2::get_cpu_size(),
            ctlr: 0,
            irq_cfg: [0; IRQ_NUM as usize],
            vcpus: BTreeMap::new(),
            irq_enabled: [false; IRQ_NUM as usize],
            vtimer_irq: GTIMER_VIRT + 16,
        }
    }

    /// Get the address of the GICv2 distributor + CPU interface.
    pub const fn get_addr() -> u64 {
        // The CPU interface mapping starts before the distributor, so use it here.
        GICv2::get_cpu_addr()
    }

    /// Get the size of the GICv2 distributor + CPU interface.
    pub const fn get_size() -> u64 {
        GICv2::get_dist_size() + GICv2::get_cpu_size()
    }

    pub fn set_irq(&mut self, irq_line: u32) {
        debug!("GIC should set irq={}", irq_line);
        // TODO - Should check target CPU for this irq
        let vcpuid = 0;

        if self.irq_enabled[irq_line as usize] {
            return;
        }

        match self.vcpus.entry(vcpuid) {
            Entry::Vacant(_) => {
                panic!("Unknown vCPU id: {}", vcpuid);
            }
            Entry::Occupied(mut vcpu_entry) => {
                let mut vcpu = vcpu_entry.get_mut();
                if irq_line != self.vtimer_irq {
                    self.irq_enabled[irq_line as usize] = true;
                }

                vcpu.pending_irqs.push_back(irq_line);

                match vcpu.status {
                    VcpuStatus::Waiting => {
                        vcpu.wfe_sender.send(0).unwrap();
                        vcpu.status = VcpuStatus::Running;
                    }
                    VcpuStatus::Running => {}
                }
            }
        }
    }

    pub fn register_vcpu(&mut self, vcpuid: u64, wfe_sender: Sender<u32>) {
        self.vcpus.insert(
            vcpuid,
            VcpuInfo {
                status: VcpuStatus::Running,
                wfe_sender,
                pending_irqs: VecDeque::new(),
            },
        );
    }

    pub fn vcpu_should_wait(&mut self, vcpuid: u64) -> bool {
        match self.vcpus.entry(vcpuid) {
            Entry::Vacant(_) => {
                panic!("Unknown vCPU id: {}", vcpuid);
            }
            Entry::Occupied(mut vcpu_entry) => {
                let mut vcpu = vcpu_entry.get_mut();
                if vcpu.pending_irqs.is_empty() {
                    vcpu.status = VcpuStatus::Waiting;
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn vcpu_has_pending_irq(&mut self, vcpuid: u64) -> bool {
        match self.vcpus.entry(vcpuid) {
            Entry::Vacant(_) => {
                panic!("Unknown vCPU id: {}", vcpuid);
            }
            Entry::Occupied(mut vcpu_entry) => {
                let vcpu = vcpu_entry.get_mut();
                if vcpu.pending_irqs.is_empty() {
                    false
                } else {
                    true
                }
            }
        }
    }

    fn get_pending_irq(&mut self) -> u32 {
        // Should check vcpu id
        let vcpuid = 0;
        match self.vcpus.entry(vcpuid) {
            Entry::Vacant(_) => {
                panic!("Unknown vCPU id: {}", vcpuid);
            }
            Entry::Occupied(mut vcpu_entry) => {
                let vcpu = vcpu_entry.get_mut();
                vcpu.pending_irqs.pop_front().unwrap_or(1023)
            }
        }
    }

    fn handle_dist_read8(&mut self, offset: u64, _data: &mut [u8]) {
        debug!("GIC DIST read8 offset=0x{:x}", offset);
    }

    fn handle_dist_read16(&mut self, offset: u64, _data: &mut [u8]) {
        debug!("GIC DIST read16 offset=0x{:x}", offset);
    }

    fn handle_dist_read32(&mut self, offset: u64, data: &mut [u8]) {
        debug!("GIC DIST read32 offset=0x{:x}", offset);
        let mut val: u32 = 0;
        match offset {
            0x0 => val = self.ctlr,
            0x4 => val = (IRQ_NUM / 32) - 1,
            0xc00..=0xf00 => {
                let irq = offset - 0xc00;
                val = self.irq_cfg[irq as usize];
                debug!("Reading irq={} val={}", irq, val);
            }
            _ => {}
        }
        for (i, b) in val.to_le_bytes().iter().enumerate() {
            data[i] = *b;
        }
        debug!("data={:?}", data);
    }

    fn handle_dist_write8(&mut self, offset: u64, data: &[u8]) {
        debug!("GIC DIST write8 offset=0x{:x}, data={:?}", offset, data);
    }

    fn handle_dist_write16(&mut self, offset: u64, data: &[u8]) {
        debug!("GIC DIST write16 offset=0x{:x}, data={:?}", offset, data);
    }

    fn handle_dist_write32(&mut self, offset: u64, data: &[u8]) {
        debug!("GIC DIST write32 offset=0x{:x}, data={:?}", offset, data);
        let val: u32 = u32::from_le_bytes(data.try_into().unwrap());
        match offset {
            0x0 => self.ctlr = val,
            0xc00..=0xeff => {
                let irq = offset - 0xc00;
                debug!("Setting irq={} to val={}", irq, val);
                self.irq_cfg[irq as usize] = val;
            }
            _ => {}
        }
    }

    fn handle_cpu_read8(&mut self, offset: u64, _data: &mut [u8]) {
        debug!("GIC CPU read8 offset=0x{:x}", offset);
    }

    fn handle_cpu_read16(&mut self, offset: u64, _data: &mut [u8]) {
        debug!("GIC CPU read16 offset=0x{:x}", offset);
    }

    fn handle_cpu_read32(&mut self, offset: u64, data: &mut [u8]) {
        debug!("GIC CPU read32 offset=0x{:x}", offset);
        let mut val = 0;
        match offset {
            0xc => {
                val = self.get_pending_irq();
                debug!("pending irq={}", val);
            }
            _ => {}
        }
        for (i, b) in val.to_le_bytes().iter().enumerate() {
            data[i] = *b;
        }
        debug!(
            "data={:?} val={}",
            data,
            u32::from_le_bytes((data as &[u8]).try_into().unwrap())
        );
    }

    fn handle_cpu_write8(&mut self, offset: u64, data: &[u8]) {
        debug!("GIC CPU write8 offset=0x{:x}, data={:?}", offset, data);
    }

    fn handle_cpu_write16(&mut self, offset: u64, data: &[u8]) {
        debug!("GIC CPU write16 offset=0x{:x}, data={:?}", offset, data);
    }

    fn handle_cpu_write32(&mut self, offset: u64, data: &[u8]) {
        debug!("GIC CPU write32 offset=0x{:x}, data={:?}", offset, data);
        let val: u32 = u32::from_le_bytes(data.try_into().unwrap());
        match offset {
            0x10 => {
                let irq = val & 0x3FF;
                debug!("EOI for irq={}", irq);
                if irq < IRQ_NUM {
                    self.irq_enabled[irq as usize] = false;
                    if irq == self.vtimer_irq {
                        // TODO - get vCPU id from target.
                        vcpu_set_vtimer_mask(0, false).unwrap();
                    }
                }
            }
            _ => {}
        }
    }
}

impl BusDevice for Gic {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if offset >= self.cpu_size {
            let offset = offset - self.cpu_size;
            match data.len() {
                1 => self.handle_dist_read8(offset, data),
                2 => self.handle_dist_read16(offset, data),
                4 => self.handle_dist_read32(offset, data),
                _ => panic!("GIC DIST unsupported read size"),
            }
        } else {
            match data.len() {
                1 => self.handle_cpu_read8(offset, data),
                2 => self.handle_cpu_read16(offset, data),
                4 => self.handle_cpu_read32(offset, data),
                _ => panic!("GIC CPU unsupported read size"),
            }
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if offset >= self.cpu_size {
            let offset = offset - self.cpu_size;
            match data.len() {
                1 => self.handle_dist_write8(offset, data),
                2 => self.handle_dist_write16(offset, data),
                4 => self.handle_dist_write32(offset, data),
                _ => panic!("GIC DIST unsupported read size"),
            }
        } else {
            match data.len() {
                1 => self.handle_cpu_write8(offset, data),
                2 => self.handle_cpu_write16(offset, data),
                4 => self.handle_cpu_write32(offset, data),
                _ => panic!("GIC CPU unsupported write size"),
            }
        }
    }
}

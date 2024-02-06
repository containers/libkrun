// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use crossbeam_channel::Sender;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::convert::TryInto;

use arch::aarch64::gicv2::GICv2;
use arch::aarch64::layout::GTIMER_VIRT;
use hvf::{vcpu_request_exit, vcpu_set_vtimer_mask};

use crate::bus::BusDevice;

const IRQ_NUM: u32 = 64;
const MAX_CPUS: u64 = 8;

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
    irq_cfg: [u8; IRQ_NUM as usize],
    vcpus: BTreeMap<u8, VcpuInfo>,
    vcpu_count: u8,
    irq_target: [u8; IRQ_NUM as usize],
    vtimer_irq: u32,
}

impl Default for Gic {
    fn default() -> Self {
        Self::new()
    }
}

impl Gic {
    pub fn new() -> Self {
        Self {
            cpu_size: GICv2::get_cpu_size(),
            ctlr: 0,
            irq_cfg: [0; IRQ_NUM as usize],
            vcpus: BTreeMap::new(),
            vcpu_count: 0,
            irq_target: [0; IRQ_NUM as usize],
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

    fn set_irq_common(&mut self, vcpuid: u8, irq_line: u32) {
        match self.vcpus.entry(vcpuid) {
            Entry::Vacant(_) => {
                panic!("Unknown vCPU id: {}", vcpuid);
            }
            Entry::Occupied(mut vcpu_entry) => {
                let vcpu = vcpu_entry.get_mut();

                vcpu.pending_irqs.push_back(irq_line);

                match vcpu.status {
                    VcpuStatus::Waiting => {
                        vcpu.wfe_sender.send(vcpuid as u32).unwrap();
                        vcpu.status = VcpuStatus::Running;
                    }
                    VcpuStatus::Running => {
                        vcpu_request_exit(vcpuid as u64).unwrap();
                    }
                }
            }
        }
    }

    pub fn set_sgi_irq(&mut self, vcpuid: u8, irq_line: u32) {
        assert!(irq_line < 16);
        self.set_irq_common(vcpuid, irq_line);
    }

    pub fn set_vtimer_irq(&mut self, vcpuid: u64) {
        assert!(vcpuid < MAX_CPUS);
        self.set_irq_common(vcpuid as u8, self.vtimer_irq);
    }

    pub fn set_irq(&mut self, irq_line: u32) {
        for vcpuid in 0..self.vcpu_count {
            if (self.irq_target[irq_line as usize] & (1 << vcpuid)) == 0 {
                continue;
            }

            debug!("signaling irq={} to vcpuid={}", irq_line, vcpuid);

            self.set_irq_common(vcpuid, irq_line);
        }
    }

    pub fn register_vcpu(&mut self, vcpuid: u64, wfe_sender: Sender<u32>) {
        assert!(vcpuid < MAX_CPUS);
        self.vcpus.insert(
            vcpuid as u8,
            VcpuInfo {
                status: VcpuStatus::Running,
                wfe_sender,
                pending_irqs: VecDeque::new(),
            },
        );
        assert!(self.vcpus.len() <= MAX_CPUS as usize);
        self.vcpu_count = self.vcpus.len() as u8;
    }

    pub fn vcpu_should_wait(&mut self, vcpuid: u64) -> bool {
        assert!(vcpuid < MAX_CPUS);
        match self.vcpus.entry(vcpuid as u8) {
            Entry::Vacant(_) => {
                panic!("Unknown vCPU id: {}", vcpuid);
            }
            Entry::Occupied(mut vcpu_entry) => {
                let vcpu = vcpu_entry.get_mut();
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
        assert!(vcpuid < MAX_CPUS);
        match self.vcpus.entry(vcpuid as u8) {
            Entry::Vacant(_) => {
                panic!("Unknown vCPU id: {}", vcpuid);
            }
            Entry::Occupied(mut vcpu_entry) => {
                let vcpu = vcpu_entry.get_mut();
                !vcpu.pending_irqs.is_empty()
            }
        }
    }

    fn get_pending_irq(&mut self, vcpuid: u8) -> u32 {
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

    fn handle_dist_read8(&mut self, vcpuid: u64, offset: u64, _data: &mut [u8]) {
        debug!("GIC DIST read8 vcpuid={} offset=0x{:x}", vcpuid, offset);
    }

    fn handle_dist_read16(&mut self, vcpuid: u64, offset: u64, _data: &mut [u8]) {
        debug!("GIC DIST read16 vcpuid={} offset=0x{:x}", vcpuid, offset);
    }

    fn handle_dist_read32(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        debug!("GIC DIST read32 vcpuid={} offset=0x{:x}", vcpuid, offset);
        let mut val: u32 = 0;
        match offset {
            0x0 => val = self.ctlr,
            0x4 => val = (IRQ_NUM / 32) - 1,
            0x800..=0x8c1 => val = 1 << vcpuid,
            0xc00..=0xf00 => {
                let first_irq = (offset - 0xc00) * 4;
                for i in 0..=15 {
                    let irq = first_irq + i;
                    val |= (self.irq_cfg[irq as usize] as u32) << ((15 - i) * 2);
                }
            }
            _ => {}
        }
        for (i, b) in val.to_le_bytes().iter().enumerate() {
            data[i] = *b;
        }
        debug!("data={:?}", data);
    }

    fn handle_dist_write8(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        debug!(
            "GIC DIST write8 vcpuid={} offset=0x{:x}, data={:?}",
            vcpuid, offset, data
        );
    }

    fn handle_dist_write16(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        debug!(
            "GIC DIST write16 vcpuid={} offset=0x{:x}, data={:?}",
            vcpuid, offset, data
        );
    }

    fn handle_dist_write32(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        debug!(
            "GIC DIST write32 vcpuid={} offset=0x{:x}, data={:?}",
            vcpuid, offset, data
        );
        let val: u32 = u32::from_le_bytes(data.try_into().unwrap());
        match offset {
            0x0 => self.ctlr = val,
            0x800..=0xbf8 => {
                let first_irq = offset - 0x800;
                for i in 0..=3 {
                    let irq = first_irq + i;
                    let cpumask: u8 = ((val >> ((3 - i) * 8)) & 0xf) as u8;
                    debug!("Configuring irq {} to cpumask {}", irq, cpumask);
                    self.irq_target[irq as usize] = cpumask;
                }
            }
            0xc00..=0xeff => {
                let first_irq = (offset - 0xc00) * 4;
                for i in 0..=15 {
                    let irq = first_irq + i;
                    let cfg: u8 = ((val >> ((15 - i) * 2)) & 0x3) as u8;
                    debug!("Configuring irq {} to cfg {}", irq, cfg);
                    self.irq_cfg[irq as usize] = cfg;
                }
            }
            0xf00 => {
                debug!("SGI requested by vcpuid={}", vcpuid);
                let irq = val & 0xf;
                let filter = val & 0x3000000;
                match filter {
                    0b01 => {
                        for cpu in 0..self.vcpu_count {
                            if cpu != vcpuid as u8 {
                                self.set_sgi_irq(cpu, irq);
                            }
                        }
                    }
                    0b10 => self.set_sgi_irq(vcpuid as u8, irq),
                    _ => {
                        let target_cpus = (val & 0xff0000) >> 16;
                        for vcpuid in 0..self.vcpu_count {
                            if (target_cpus & (1 << vcpuid)) != 0 {
                                debug!("signal irq={} to vcpu: {}", irq, vcpuid);
                                self.set_sgi_irq(vcpuid, irq);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_cpu_read8(&mut self, vcpuid: u64, offset: u64, _data: &mut [u8]) {
        debug!("GIC CPU read8 vcpuid={} offset=0x{:x}", vcpuid, offset);
    }

    fn handle_cpu_read16(&mut self, vcpuid: u64, offset: u64, _data: &mut [u8]) {
        debug!("GIC CPU read16 vcpuid={} offset=0x{:x}", vcpuid, offset);
    }

    fn handle_cpu_read32(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        debug!("GIC CPU read32 vcpuid={} offset=0x{:x}", vcpuid, offset);
        assert!(vcpuid < MAX_CPUS);

        let mut val = 0;
        if offset == 0xc {
            val = self.get_pending_irq(vcpuid as u8);
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

    fn handle_cpu_write8(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        debug!(
            "GIC CPU write8 vcpuid={} offset=0x{:x}, data={:?}",
            vcpuid, offset, data
        );
    }

    fn handle_cpu_write16(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        debug!(
            "GIC CPU write16 vcpuid={} offset=0x{:x}, data={:?}",
            vcpuid, offset, data
        );
    }

    fn handle_cpu_write32(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        debug!(
            "GIC CPU write32 vcpuid={} offset=0x{:x}, data={:?}",
            vcpuid, offset, data
        );
        let val: u32 = u32::from_le_bytes(data.try_into().unwrap());

        if offset == 0x10 {
            let irq = val & 0x3FF;
            if irq < IRQ_NUM && irq == self.vtimer_irq {
                vcpu_set_vtimer_mask(vcpuid, false).unwrap();
            }
        }
    }
}

impl BusDevice for Gic {
    fn read(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        if offset >= self.cpu_size {
            let offset = offset - self.cpu_size;
            match data.len() {
                1 => self.handle_dist_read8(vcpuid, offset, data),
                2 => self.handle_dist_read16(vcpuid, offset, data),
                4 => self.handle_dist_read32(vcpuid, offset, data),
                _ => panic!("GIC DIST unsupported read size"),
            }
        } else {
            match data.len() {
                1 => self.handle_cpu_read8(vcpuid, offset, data),
                2 => self.handle_cpu_read16(vcpuid, offset, data),
                4 => self.handle_cpu_read32(vcpuid, offset, data),
                _ => panic!("GIC CPU unsupported read size"),
            }
        }
    }

    fn write(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        if offset >= self.cpu_size {
            let offset = offset - self.cpu_size;
            match data.len() {
                1 => self.handle_dist_write8(vcpuid, offset, data),
                2 => self.handle_dist_write16(vcpuid, offset, data),
                4 => self.handle_dist_write32(vcpuid, offset, data),
                _ => panic!("GIC DIST unsupported read size"),
            }
        } else {
            match data.len() {
                1 => self.handle_cpu_write8(vcpuid, offset, data),
                2 => self.handle_cpu_write16(vcpuid, offset, data),
                4 => self.handle_cpu_write32(vcpuid, offset, data),
                _ => panic!("GIC CPU unsupported write size"),
            }
        }
    }
}

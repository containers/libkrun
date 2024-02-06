// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{boxed::Box, result};

use super::gic::{Error, GICDevice};

type Result<T> = result::Result<T, Error>;

/// This is just a placeholder for building the FDT entry.
/// The actual emulated GICv2 is in devices/legacy.
pub struct GICv2 {
    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

impl GICv2 {
    // Unfortunately bindgen omits defines that are based on other defines.
    // See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
    const GIC_V2_DIST_SIZE: u64 = 0x1000;
    const GIC_V2_CPU_SIZE: u64 = 0x2000;

    // Device trees specific constants
    const GIC_V2_MAINT_IRQ: u32 = 8;

    /// Get the address of the GICv2 distributor.
    pub const fn get_dist_addr() -> u64 {
        super::super::layout::MAPPED_IO_START - GICv2::GIC_V2_DIST_SIZE
    }

    /// Get the size of the GIC_v2 distributor.
    pub const fn get_dist_size() -> u64 {
        GICv2::GIC_V2_DIST_SIZE
    }

    /// Get the address of the GIC_v2 CPU.
    pub const fn get_cpu_addr() -> u64 {
        GICv2::get_dist_addr() - GICv2::GIC_V2_CPU_SIZE
    }

    /// Get the size of the GIC_v2 CPU.
    pub const fn get_cpu_size() -> u64 {
        GICv2::GIC_V2_CPU_SIZE
    }
}

impl GICDevice for GICv2 {
    fn version() -> u32 {
        0
    }

    fn device_properties(&self) -> &[u64] {
        &self.properties
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> &str {
        "arm,cortex-a15-gic"
    }

    fn fdt_maint_irq(&self) -> u32 {
        GICv2::GIC_V2_MAINT_IRQ
    }

    fn create_device(vcpu_count: u64) -> Box<dyn GICDevice> {
        Box::new(GICv2 {
            properties: [
                GICv2::get_dist_addr(),
                GICv2::get_dist_size(),
                GICv2::get_cpu_addr(),
                GICv2::get_cpu_size(),
            ],
            vcpu_count,
        })
    }

    fn init_device_attributes(_gic_device: &Box<dyn GICDevice>) -> Result<()> {
        /* Setting up the distributor attribute.
        We are placing the GIC below 1GB so we need to substract the size of the distributor. */
        Ok(())
    }
}

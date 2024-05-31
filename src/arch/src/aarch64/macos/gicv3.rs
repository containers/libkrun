use std::{boxed::Box, result};

use super::gic::{Error, GICDevice};

type Result<T> = result::Result<T, Error>;

/// This is just a placeholder for building the FDT entry.
/// The actual emulated GICv3 is in devices/legacy.
pub struct GICv3 {
    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

impl GICv3 {
    const SZ_64K: u64 = 0x0001_0000;

    // Device trees specific constants
    const GIC_V3_MAINT_IRQ: u32 = 8;

    /// Get the address of the GICv3 distributor.
    pub fn get_dist_addr() -> u64 {
        super::super::layout::MAPPED_IO_START - 3 * GICv3::SZ_64K
    }

    /// Get the size of the GIC_v3 distributor.
    pub const fn get_dist_size() -> u64 {
        GICv3::SZ_64K
    }

    /// Get the address of the GIC redistributors.
    pub const fn compute_redists_addr(vcpu_count: u64) -> u64 {
        super::super::layout::MAPPED_IO_START
            - 3 * GICv3::SZ_64K
            - GICv3::compute_redists_size(vcpu_count)
    }

    pub fn get_redists_addr(&self) -> u64 {
        Self::compute_redists_addr(self.vcpu_count)
    }

    /// Get the size of the GIC redistributors.
    pub const fn compute_redists_size(vcpu_count: u64) -> u64 {
        vcpu_count * GICv3::get_redist_size()
    }

    pub fn get_redists_size(&self) -> u64 {
        GICv3::compute_redists_size(self.vcpu_count)
    }

    pub const fn get_redist_size() -> u64 {
        2 * GICv3::SZ_64K
    }
}

impl GICDevice for GICv3 {
    fn device_properties(&self) -> &[u64] {
        &self.properties
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> &str {
        "arm,gic-v3"
    }

    fn fdt_maint_irq(&self) -> u32 {
        GICv3::GIC_V3_MAINT_IRQ
    }

    fn version() -> u32 {
        0
    }

    fn create_device(vcpu_count: u64) -> Box<dyn GICDevice> {
        Box::new(GICv3 {
            properties: [
                GICv3::get_dist_addr(),
                GICv3::get_dist_size(),
                GICv3::compute_redists_addr(vcpu_count),
                GICv3::compute_redists_size(vcpu_count),
            ],
            vcpu_count,
        })
    }

    fn init_device_attributes(_gic_device: &Box<dyn GICDevice>) -> Result<()> {
        Ok(())
    }
}

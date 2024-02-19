// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{boxed::Box, result};

use super::gicv2::GICv2;

/// Errors thrown while setting up the GIC.
#[derive(Debug)]
pub enum Error {}
type Result<T> = result::Result<T, Error>;

/// Trait for GIC devices.
pub trait GICDevice: Send {
    /// Returns an array with GIC device properties
    fn device_properties(&self) -> &[u64];

    /// Returns the number of vCPUs this GIC handles
    fn vcpu_count(&self) -> u64;

    /// Returns the fdt compatibility property of the device
    fn fdt_compatibility(&self) -> &str;

    /// Returns the maint_irq fdt property of the device
    fn fdt_maint_irq(&self) -> u32;

    /// Returns the GIC version of the device
    fn version() -> u32
    where
        Self: Sized;

    /// Create the GIC device object
    fn create_device(vcpu_count: u64) -> Box<dyn GICDevice>
    where
        Self: Sized;

    /// Setup the device-specific attributes
    fn init_device_attributes(gic_device: &Box<dyn GICDevice>) -> Result<()>
    where
        Self: Sized;

    /// Set a GIC device attribute
    fn set_device_attribute(_group: u32, _attr: u64, _addr: u64, _flags: u32) -> Result<()>
    where
        Self: Sized,
    {
        Ok(())
    }

    /// Finalize the setup of a GIC device
    fn finalize_device(_gic_device: &Box<dyn GICDevice>) -> Result<()>
    where
        Self: Sized,
    {
        Ok(())
    }

    /// Method to initialize the GIC device
    fn new(vcpu_count: u64) -> Result<Box<dyn GICDevice>>
    where
        Self: Sized,
    {
        let device = Self::create_device(vcpu_count);

        Self::init_device_attributes(&device)?;

        Self::finalize_device(&device)?;

        Ok(device)
    }
}

/// Create a GIC device.
///
/// It will try to create by default a GICv3 device. If that fails it will try
/// to fall-back to a GICv2 device.
pub fn create_gic(vcpu_count: u64) -> Result<Box<dyn GICDevice>> {
    GICv2::new(vcpu_count)
}

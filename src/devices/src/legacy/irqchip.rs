use std::sync::{Arc, Mutex};

use crate::bus::BusDevice;
#[cfg(target_arch = "aarch64")]
use crate::legacy::gic::GICDevice;
use crate::Error as DeviceError;

use utils::eventfd::EventFd;

pub type IrqChip = Arc<Mutex<IrqChipDevice>>;

pub struct IrqChipDevice {
    inner: Box<dyn IrqChipT>,
}

impl IrqChipDevice {
    pub fn new(irqchip: Box<dyn IrqChipT>) -> Self {
        Self { inner: irqchip }
    }

    pub fn get_mmio_addr(&self) -> u64 {
        self.inner.get_mmio_addr()
    }

    pub fn get_mmio_size(&self) -> u64 {
        self.inner.get_mmio_size()
    }

    pub fn set_irq(
        &self,
        irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        self.inner.set_irq(irq_line, interrupt_evt)
    }
}

impl BusDevice for IrqChipDevice {
    fn read(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        self.inner.read(vcpuid, offset, data)
    }

    fn write(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        self.inner.write(vcpuid, offset, data)
    }
}

#[cfg(target_arch = "aarch64")]
impl GICDevice for IrqChipDevice {
    /// Returns an array with GIC device properties
    fn device_properties(&self) -> Vec<u64> {
        self.inner.device_properties().clone()
    }

    /// Returns the number of vCPUs this GIC handles
    fn vcpu_count(&self) -> u64 {
        self.inner.vcpu_count()
    }

    /// Returns the fdt compatibility property of the device
    fn fdt_compatibility(&self) -> String {
        self.inner.fdt_compatibility().clone()
    }

    /// Returns the maint_irq fdt property of the device
    fn fdt_maint_irq(&self) -> u32 {
        self.inner.fdt_maint_irq()
    }

    /// Returns the GIC version of the device
    fn version(&self) -> u32 {
        self.inner.version()
    }
}

#[cfg(target_arch = "x86_64")]
pub trait IrqChipT: BusDevice {
    fn get_mmio_addr(&self) -> u64;
    fn get_mmio_size(&self) -> u64;
    fn set_irq(
        &self,
        irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError>;
}

#[cfg(target_arch = "aarch64")]
pub trait IrqChipT: BusDevice + GICDevice {
    fn get_mmio_addr(&self) -> u64;
    fn get_mmio_size(&self) -> u64;
    fn set_irq(
        &self,
        irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError>;
}

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils {
    use super::*;

    #[derive(Clone, Default, Debug)]
    pub struct DummyIrqChip {}

    impl DummyIrqChip {
        pub fn new() -> Self {
            Default::default()
        }
    }

    impl Into<IrqChip> for DummyIrqChip {
        fn into(self) -> IrqChip {
            Arc::new(Mutex::new(IrqChipDevice::new(
                Box::new(DummyIrqChip::new()),
            )))
        }
    }

    impl BusDevice for DummyIrqChip {}

    impl IrqChipT for DummyIrqChip {
        fn get_mmio_addr(&self) -> u64 {
            0
        }
        fn get_mmio_size(&self) -> u64 {
            0
        }
        fn set_irq(
            &self,
            _irq_line: Option<u32>,
            _interrupt_evt: Option<&EventFd>,
        ) -> Result<(), DeviceError> {
            Ok(())
        }
    }
}

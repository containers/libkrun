use std::fs::File;
use std::io;

use crate::bus::BusDevice;
use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;

use kvm_bindings::kvm_interrupt;
use kvm_ioctls::{DeviceFd, Error as KvmError, VmFd};
use utils::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::ioctl_iow_nr;

ioctl_iow_nr!(
    KVM_INTERRUPT_LOONGARCH,
    kvm_bindings::KVMIO,
    0x86,
    kvm_interrupt
);

pub struct KvmLoongArchIrqChip {
    _ipi_fd: DeviceFd,
    _eiointc_fd: DeviceFd,
    _pchpic_fd: DeviceFd,
    irq_vcpu_fd: File,
    _vcpu_count: u32,
}

impl KvmLoongArchIrqChip {
    pub fn new(vm: &VmFd, vcpu_count: u32, irq_vcpu_fd: File) -> Result<Self, KvmError> {
        // Keep the in-kernel external irqchip devices around for platform
        // compatibility; the active serial/virtio injection path uses
        // KVM_INTERRUPT through cpuintc on vcpu0.
        let mut ipi_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_LOONGARCH_IPI,
            fd: 0,
            flags: 0,
        };
        let ipi_fd = vm.create_device(&mut ipi_device)?;

        let mut eiointc_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_LOONGARCH_EIOINTC,
            fd: 0,
            flags: 0,
        };
        let eiointc_fd = vm.create_device(&mut eiointc_device)?;

        let nr_cpus = vcpu_count;
        let nr_cpu_ptr = &nr_cpus as *const u32;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_LOONGARCH_EXTIOI_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_LOONGARCH_EXTIOI_CTRL_INIT_NUM_CPU),
            addr: nr_cpu_ptr as u64,
            flags: 0,
        };
        eiointc_fd.set_device_attr(&attr)?;
        let features: u32 = 0;
        let features_ptr = &features as *const u32;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_LOONGARCH_EXTIOI_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_LOONGARCH_EXTIOI_CTRL_INIT_FEATURE),
            addr: features_ptr as u64,
            flags: 0,
        };
        eiointc_fd.set_device_attr(&attr)?;

        let mut pchpic_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_LOONGARCH_PCHPIC,
            fd: 0,
            flags: 0,
        };
        let pchpic_fd = vm.create_device(&mut pchpic_device)?;
        let pch_pic_base: u64 = 0x1000_0000;
        let pch_pic_base_ptr = &pch_pic_base as *const u64;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_LOONGARCH_PCH_PIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_LOONGARCH_PCH_PIC_CTRL_INIT),
            addr: pch_pic_base_ptr as u64,
            flags: 0,
        };
        pchpic_fd.set_device_attr(&attr)?;

        Ok(Self {
            _ipi_fd: ipi_fd,
            _eiointc_fd: eiointc_fd,
            _pchpic_fd: pchpic_fd,
            irq_vcpu_fd,
            _vcpu_count: vcpu_count,
        })
    }
}

impl IrqChipT for KvmLoongArchIrqChip {
    fn get_mmio_addr(&self) -> u64 {
        0x1000_0000
    }

    fn get_mmio_size(&self) -> u64 {
        0x400
    }

    fn set_irq(
        &self,
        irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        //debug!("loongarch irqchip set_irq_state irq_line={:?}", irq_line);
        // LoongArch mmio/serial path does not rely on irqfd registration.
        // Inject via KVM_INTERRUPT (assert).
        if let Err(e) = self.set_irq_state(irq_line, interrupt_evt, true) {
            error!("Failed to set irq state: {e:?}");
            return Err(e);
        }
        //debug!("loongarch irqchip eventfd write ok");
        Ok(())
    }

    fn set_irq_state(
        &self,
        irq_line: Option<u32>,
        _interrupt_evt: Option<&EventFd>,
        active: bool,
    ) -> Result<(), DeviceError> {
        let irq = match irq_line {
            Some(irq) => irq,
            None => {
                return Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "irq_line not set",
                )));
            }
        };

        let signed_irq = if active { irq as i32 } else { -(irq as i32) };
        let interrupt = kvm_interrupt {
            // KVM uapi exposes `irq` as u32, but LoongArch KVM casts it back to `int`
            // and uses the sign to distinguish assert vs deassert.
            irq: signed_irq as u32,
        };

        let ret =
            unsafe { ioctl_with_ref(&self.irq_vcpu_fd, KVM_INTERRUPT_LOONGARCH(), &interrupt) };
        if ret != 0 {
            let e = io::Error::last_os_error();
            error!(
                "KVM_INTERRUPT failed: irq={}, signed_irq={}, active={}, err={e:?}",
                irq, signed_irq, active
            );
            return Err(DeviceError::FailedSignalingUsedQueue(e));
        }

        // debug!(
        //     "KVM_INTERRUPT ok: irq={}, signed_irq={}, active={}",
        //     irq, signed_irq, active
        // );
        Ok(())
    }
}

impl BusDevice for KvmLoongArchIrqChip {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

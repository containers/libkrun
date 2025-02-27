use tdx::launch::{TdxCapabilities, TdxVm};

use kvm_ioctls::VmFd;

use std::fs::File;

#[derive(Debug)]
pub enum Error {
    CreateTdxVmStruct,
    GetCapabilities,
    InitVm,
    InitMemoryRegions(i32),
}

pub struct IntelTdx {
    caps: TdxCapabilities,
    vm: TdxVm,
}

impl IntelTdx {
    pub fn new(vm_fd: &VmFd, vcpu_count: u8) -> Result<Self, Error> {
        let vm = TdxVm::new(vm_fd, vcpu_count as u64)
            .or_else(|_| return Err(Error::CreateTdxVmStruct))?;
        let caps = vm
            .get_capabilities(vm_fd)
            .or_else(|_| return Err(Error::GetCapabilities))?;

        Ok(IntelTdx { caps, vm })
    }

    pub fn vm_prepare(
        &self,
        fd: &kvm_ioctls::VmFd,
        cpuid: kvm_bindings::CpuId,
    ) -> Result<(), Error> {
        self.vm
            .init_vm(fd, cpuid)
            .or_else(|_| return Err(Error::InitVm))?;

        Ok(())
    }

    pub fn configure_td_memory(
        &self,
        fd: &kvm_ioctls::VmFd,
        regions: &Vec<crate::vstate::MeasuredRegion>,
    ) -> Result<(), Error> {
        for region in regions {
            let ext = if arch::BIOS_START == region.guest_addr {
                1
            } else {
                0
            };

            if let Err(e) = self.vm.init_mem_region(
                fd,
                region.guest_addr,
                (region.size / 4096) as u64,
                ext,
                region.host_addr,
            ) {
                if e.code != libc::EAGAIN {
                    return Err(Error::InitMemoryRegions(e.code));
                }
            }
        }

        Ok(())
    }
}

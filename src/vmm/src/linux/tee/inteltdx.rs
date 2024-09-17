use tdx::launch::{TdxCapabilities, TdxVm};

use kvm_ioctls::VmFd;

use std::fs::File;

#[derive(Debug)]
pub enum Error {
    CreateTdxVmStruct,
    GetCapabilities,
    InitVm,
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
}

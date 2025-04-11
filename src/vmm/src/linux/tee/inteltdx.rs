use tdx::launch::{TdxCapabilities, TdxVm};
use tdx::tdvf::{self, TdvfSection};

use kvm_ioctls::VmFd;

use std::fs::File;
use std::io;

#[derive(Debug)]
pub enum Error {
    CreateTdxVmStruct,
    GetCapabilities,
    InitVm,
    InitMemoryRegions(i32),
    OpenTdvfFirmwareFile(io::Error),
    ParseTdvfSections(tdvf::Error),
    FinalizeVm,
}

pub struct IntelTdx {
    caps: TdxCapabilities,
    vm: TdxVm,
    tdvf_sections: Vec<TdvfSection>,
    tdvf_file: File,
}

impl IntelTdx {
    pub fn new(vm_fd: &VmFd, vcpu_count: u8) -> Result<Self, Error> {
        let vm = TdxVm::new(vm_fd, vcpu_count as u64).or_else(|_| return Err(Error::CreateTdxVmStruct))?;
        let caps = vm
            .get_capabilities(vm_fd)
            .or_else(|_| return Err(Error::GetCapabilities))?;

        let mut firmware = std::fs::File::open("/usr/share/edk2/ovmf/OVMF.inteltdx.fd")
            .map_err(Error::OpenTdvfFirmwareFile)?;
        let tdvf_sections =
            tdx::tdvf::parse_sections(&mut firmware).map_err(Error::ParseTdvfSections)?;

        Ok(IntelTdx {
            caps,
            vm,
            tdvf_sections,
            tdvf_file: firmware,
        })
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

    pub fn configure_td_memory(&self, fd: &kvm_ioctls::VmFd, regions: &Vec<crate::vstate::MeasuredRegion>) -> Result<(), Error> {
        for region in regions {
            let ext = if arch::BIOS_START == region.guest_addr {
                1
            } else {
                0
            };

            if let Err(e) = self.vm.init_mem_region(fd, region.guest_addr, (region.size / 4096) as u64, ext, region.host_addr) {
                if e.code != libc::EAGAIN {
                    return Err(Error::InitMemoryRegions(e.code));
                }
            }
        }
        
        Ok(())
    }

    pub fn finalize_vm(&self, fd: &kvm_ioctls::VmFd) -> Result<(), Error> {
        self.vm.finalize(fd).or_else(|_| return Err(Error::FinalizeVm))
    }
}

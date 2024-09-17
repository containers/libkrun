use kvm_ioctls::VmFd;
use tdx::launch::{self, Launcher};

use std::os::unix::io::AsRawFd;

#[derive(Debug)]
pub enum Error {
    GetCapabilities(launch::Error),
    InitVm(launch::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub struct IntelTdx {}

impl IntelTdx {
    pub fn new() -> Self {
        Self {}
    }

    pub fn vm_prepare(&self, vm_fd: &VmFd, cpuid: kvm_bindings::CpuId) -> Result<Launcher> {
        let mut launcher = Launcher::new(vm_fd.as_raw_fd());
        let caps = launcher
            .get_capabilities()
            .map_err(Error::GetCapabilities)?;
        launcher.init_vm(&caps, cpuid).map_err(Error::InitVm)?;
        Ok(launcher)
    }
}

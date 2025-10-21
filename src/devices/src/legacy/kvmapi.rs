use kvm_ioctls::{Error, VmFd};

#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
use crate::legacy::KvmAia;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::legacy::KvmIoapic;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use crate::legacy::{KvmGicV2, KvmGicV3};

pub enum KvmApi {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    KvmIoapic(KvmIoapic),
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    KvmGicV2(KvmGicV2),
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    KvmGicV3(KvmGicV3),
    #[cfg(all(target_os = "linux", target_arch = "riscv64"))]
    KvmAia(KvmAia),
}

impl KvmApi {
    #[cfg(all(target_os = "linux", target_arch = "riscv64"))]
    pub fn new(vm: &VmFd, vcpu_count: u64) -> Result<Self, Error> {
        let kvmaia = KvmAia::new(vm, vcpu_count as _).unwrap();
        Ok(Self::KvmAia(kvmaia))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub fn new(vm: &VmFd, _vcpu_count: u64) -> Result<Self, Error> {
        let kvmioapic = KvmIoapic::new(vm).unwrap();
        Ok(Self::KvmIoapic(kvmioapic))
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub fn new(vm: &VmFd, vcpu_count: u64) -> Result<Self, Error> {
        if let Ok(v3) = KvmGicV3::new(vm, vcpu_count.into()) {
            Ok(Self::KvmGicV3(v3))
        } else {
            log::warn!("GICv3 creation failed, falling back to GICv2");
            Ok(Self::KvmGicV2(KvmGicV2::new(vm, vcpu_count.into())))
        }
    }
}

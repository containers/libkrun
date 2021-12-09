// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//#![deny(warnings)]

#[cfg(feature = "amd-sev")]
use crate::vmm_config::block::{BlockBuilder, BlockConfigError, BlockDeviceConfig};
use crate::vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
#[cfg(not(feature = "amd-sev"))]
use crate::vmm_config::fs::*;
#[cfg(feature = "amd-sev")]
use crate::vmm_config::kernel_bundle::{InitrdBundle, QbootBundle, QbootBundleError};
use crate::vmm_config::kernel_bundle::{KernelBundle, KernelBundleError};
use crate::vmm_config::logger::LoggerConfigError;
use crate::vmm_config::machine_config::{VmConfig, VmConfigError};
use crate::vmm_config::vsock::*;
use crate::vstate::VcpuConfig;

type Result<E> = std::result::Result<(), E>;

/// Errors encountered when configuring microVM resources.
#[derive(Debug)]
pub enum Error {
    /// JSON is invalid.
    InvalidJson,
    /// Boot source configuration error.
    BootSource(BootSourceConfigError),
    /// Fs device configuration error.
    #[cfg(not(feature = "amd-sev"))]
    FsDevice(FsConfigError),
    /// Logger configuration error.
    Logger(LoggerConfigError),
    /// microVM vCpus or memory configuration error.
    VmConfig(VmConfigError),
    /// Vsock device configuration error.
    VsockDevice(VsockConfigError),
}

/// A data structure that encapsulates the device configurations
/// held in the Vmm.
#[derive(Default)]
pub struct VmResources {
    /// The vCpu and memory configuration for this microVM.
    vm_config: VmConfig,
    /// The boot configuration for this microVM.
    pub boot_config: BootSourceConfig,
    /// The parameters for the kernel bundle to be loaded in this microVM.
    pub kernel_bundle: Option<KernelBundle>,
    /// The parameters for the qboot bundle to be loaded in this microVM.
    #[cfg(feature = "amd-sev")]
    pub qboot_bundle: Option<QbootBundle>,
    /// The parameters for the initrd bundle to be loaded in this microVM.
    #[cfg(feature = "amd-sev")]
    pub initrd_bundle: Option<InitrdBundle>,
    /// The fs device.
    #[cfg(not(feature = "amd-sev"))]
    pub fs: FsBuilder,
    /// The vsock device.
    pub vsock: VsockBuilder,
    /// The virtio-blk device.
    #[cfg(feature = "amd-sev")]
    pub block: BlockBuilder,
    /// Base URL for the attestation server.
    #[cfg(feature = "amd-sev")]
    pub attestation_url: Option<String>,
}

impl VmResources {
    /// Returns a VcpuConfig based on the vm config.
    pub fn vcpu_config(&self) -> VcpuConfig {
        // The unwraps are ok to use because the values are initialized using defaults if not
        // supplied by the user.
        VcpuConfig {
            vcpu_count: self.vm_config().vcpu_count.unwrap(),
            ht_enabled: self.vm_config().ht_enabled.unwrap(),
            cpu_template: self.vm_config().cpu_template,
        }
    }

    /// Returns the VmConfig.
    pub fn vm_config(&self) -> &VmConfig {
        &self.vm_config
    }

    /// Set the machine configuration of the microVM.
    pub fn set_vm_config(&mut self, machine_config: &VmConfig) -> Result<VmConfigError> {
        if machine_config.vcpu_count == Some(0) {
            return Err(VmConfigError::InvalidVcpuCount);
        }

        if machine_config.mem_size_mib == Some(0) {
            return Err(VmConfigError::InvalidMemorySize);
        }

        let ht_enabled = machine_config
            .ht_enabled
            .unwrap_or_else(|| self.vm_config.ht_enabled.unwrap());

        let vcpu_count_value = machine_config
            .vcpu_count
            .unwrap_or_else(|| self.vm_config.vcpu_count.unwrap());

        // If hyperthreading is enabled or is to be enabled in this call
        // only allow vcpu count to be 1 or even.
        if ht_enabled && vcpu_count_value > 1 && vcpu_count_value % 2 == 1 {
            return Err(VmConfigError::InvalidVcpuCount);
        }

        // Update all the fields that have a new value.
        self.vm_config.vcpu_count = Some(vcpu_count_value);
        self.vm_config.ht_enabled = Some(ht_enabled);

        if machine_config.mem_size_mib.is_some() {
            self.vm_config.mem_size_mib = machine_config.mem_size_mib;
        }

        if machine_config.cpu_template.is_some() {
            self.vm_config.cpu_template = machine_config.cpu_template;
        }

        Ok(())
    }

    /// Set the guest boot source configuration.
    pub fn set_boot_source(
        &mut self,
        boot_source_cfg: BootSourceConfig,
    ) -> Result<BootSourceConfigError> {
        self.boot_config = boot_source_cfg;
        Ok(())
    }

    pub fn kernel_bundle(&self) -> Option<&KernelBundle> {
        self.kernel_bundle.as_ref()
    }

    pub fn set_kernel_bundle(&mut self, kernel_bundle: KernelBundle) -> Result<KernelBundleError> {
        // Safe because this call just returns the page size and doesn't have any side effects.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

        if kernel_bundle.host_addr == 0 || (kernel_bundle.host_addr as usize) & (page_size - 1) != 0
        {
            return Err(KernelBundleError::InvalidHostAddress);
        }

        if (kernel_bundle.guest_addr as usize) & (page_size - 1) != 0 {
            return Err(KernelBundleError::InvalidGuestAddress);
        }

        if kernel_bundle.size & (page_size - 1) != 0 {
            return Err(KernelBundleError::InvalidSize);
        }

        self.kernel_bundle = Some(kernel_bundle);
        Ok(())
    }

    #[cfg(feature = "amd-sev")]
    pub fn qboot_bundle(&self) -> Option<&QbootBundle> {
        self.qboot_bundle.as_ref()
    }

    #[cfg(feature = "amd-sev")]
    pub fn set_qboot_bundle(&mut self, qboot_bundle: QbootBundle) -> Result<QbootBundleError> {
        if qboot_bundle.size != 0x10000 {
            return Err(QbootBundleError::InvalidSize);
        }

        self.qboot_bundle = Some(qboot_bundle);
        Ok(())
    }

    #[cfg(feature = "amd-sev")]
    pub fn initrd_bundle(&self) -> Option<&InitrdBundle> {
        self.initrd_bundle.as_ref()
    }

    #[cfg(feature = "amd-sev")]
    pub fn set_initrd_bundle(&mut self, initrd_bundle: InitrdBundle) -> Result<KernelBundleError> {
        self.initrd_bundle = Some(initrd_bundle);
        Ok(())
    }

    #[cfg(not(feature = "amd-sev"))]
    pub fn set_fs_device(&mut self, config: FsDeviceConfig) -> Result<FsConfigError> {
        self.fs.insert(config)
    }

    #[cfg(feature = "amd-sev")]
    pub fn set_block_device(&mut self, config: BlockDeviceConfig) -> Result<BlockConfigError> {
        self.block.insert(config)
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn set_vsock_device(&mut self, config: VsockDeviceConfig) -> Result<VsockConfigError> {
        self.vsock.insert(config)
    }

    #[cfg(feature = "amd-sev")]
    pub fn attestation_url(&self) -> Option<String> {
        self.attestation_url.clone()
    }

    #[cfg(feature = "amd-sev")]
    pub fn set_attestation_url(&mut self, url: String) {
        self.attestation_url = Some(url);
    }
}

#[cfg(test)]
mod tests {
    use crate::resources::VmResources;
    use crate::vmm_config::boot_source::BootSourceConfig;
    use crate::vmm_config::machine_config::{CpuFeaturesTemplate, VmConfig, VmConfigError};
    use crate::vmm_config::vsock::tests::{default_config, TempSockFile};
    use crate::vstate::VcpuConfig;
    use utils::tempfile::TempFile;

    fn default_boot_cfg() -> BootSourceConfig {
        BootSourceConfig {
            kernel_cmdline_prolog: None,
            kernel_cmdline_epilog: None,
        }
    }

    fn default_vm_resources() -> VmResources {
        VmResources {
            vm_config: VmConfig::default(),
            boot_config: default_boot_cfg(),
            kernel_bundle: Default::default(),
            fs: Default::default(),
            vsock: Default::default(),
        }
    }

    #[test]
    fn test_vcpu_config() {
        let vm_resources = default_vm_resources();
        let expected_vcpu_config = VcpuConfig {
            vcpu_count: vm_resources.vm_config().vcpu_count.unwrap(),
            ht_enabled: vm_resources.vm_config().ht_enabled.unwrap(),
            cpu_template: vm_resources.vm_config().cpu_template,
        };

        let vcpu_config = vm_resources.vcpu_config();
        assert_eq!(vcpu_config, expected_vcpu_config);
    }

    #[test]
    fn test_vm_config() {
        let vm_resources = default_vm_resources();
        let expected_vm_cfg = VmConfig::default();

        assert_eq!(vm_resources.vm_config(), &expected_vm_cfg);
    }

    #[test]
    fn test_set_vm_config() {
        let mut vm_resources = default_vm_resources();
        let mut aux_vm_config = VmConfig {
            vcpu_count: Some(32),
            mem_size_mib: Some(512),
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };

        assert_ne!(vm_resources.vm_config, aux_vm_config);
        vm_resources.set_vm_config(&aux_vm_config).unwrap();
        assert_eq!(vm_resources.vm_config, aux_vm_config);

        // Invalid vcpu count.
        aux_vm_config.vcpu_count = Some(0);
        assert_eq!(
            vm_resources.set_vm_config(&aux_vm_config),
            Err(VmConfigError::InvalidVcpuCount)
        );
        aux_vm_config.vcpu_count = Some(33);
        assert_eq!(
            vm_resources.set_vm_config(&aux_vm_config),
            Err(VmConfigError::InvalidVcpuCount)
        );
        aux_vm_config.vcpu_count = Some(32);

        // Invalid mem_size_mib.
        aux_vm_config.mem_size_mib = Some(0);
        assert_eq!(
            vm_resources.set_vm_config(&aux_vm_config),
            Err(VmConfigError::InvalidMemorySize)
        );
    }

    #[test]
    fn test_set_vsock_device() {
        let mut vm_resources = default_vm_resources();
        let tmp_sock_file = TempSockFile::new(TempFile::new().unwrap());
        let new_vsock_cfg = default_config(&tmp_sock_file);
        assert!(vm_resources.vsock.get().is_none());
        vm_resources
            .set_vsock_device(new_vsock_cfg.clone())
            .unwrap();
        let actual_vsock_cfg = vm_resources.vsock.get().unwrap();
        assert_eq!(
            actual_vsock_cfg.lock().unwrap().id(),
            &new_vsock_cfg.vsock_id
        );
    }
}

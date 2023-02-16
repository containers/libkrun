// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// Firecracker aims to support small scale workloads only, so limit the maximum
/// vCPUs supported.
pub const MAX_SUPPORTED_VCPUS: u8 = 32;

/// Errors associated with configuring the microVM.
#[derive(Debug, Eq, PartialEq)]
pub enum VmConfigError {
    /// The vcpu count is invalid. When hyperthreading is enabled, the `cpu_count` must be either
    /// 1 or an even number.
    InvalidVcpuCount,
    /// The memory size is invalid. The memory can only be an unsigned integer.
    InvalidMemorySize,
}

impl fmt::Display for VmConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VmConfigError::*;
        match *self {
            InvalidVcpuCount => write!(
                f,
                "The vCPU number is invalid! The vCPU number can only \
                 be 1 or an even number when hyperthreading is enabled.",
            ),
            InvalidMemorySize => write!(f, "The memory size (MiB) is invalid.",),
        }
    }
}

/// Strongly typed structure that represents the configuration of the
/// microvm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmConfig {
    /// The number of vCPUs.
    pub vcpu_count: Option<u8>,
    /// The memory size in MiB.
    pub mem_size_mib: Option<usize>,
    /// Enables or disabled hyperthreading.
    pub ht_enabled: Option<bool>,
    /// A CPU template that it is used to filter the CPU features exposed to the guest.
    pub cpu_template: Option<CpuFeaturesTemplate>,
}

impl Default for VmConfig {
    fn default() -> Self {
        VmConfig {
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
            ht_enabled: Some(false),
            cpu_template: None,
        }
    }
}

impl fmt::Display for VmConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let vcpu_count = self.vcpu_count.unwrap_or(1);
        let mem_size = self.mem_size_mib.unwrap_or(128);
        let ht_enabled = self.ht_enabled.unwrap_or(false);
        let cpu_template = self
            .cpu_template
            .map_or("Uninitialized".to_string(), |c| c.to_string());

        write!(f, "{{ \"vcpu_count\": {vcpu_count:?}, \"mem_size_mib\": {mem_size:?},  \"ht_enabled\": {ht_enabled:?},  \"cpu_template\": {cpu_template:?} }}")
    }
}

/// Template types available for configuring the CPU features that map
/// to EC2 instances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuFeaturesTemplate {
    /// C3 Template.
    C3,
    /// T2 Template.
    T2,
}

impl fmt::Display for CpuFeaturesTemplate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CpuFeaturesTemplate::C3 => write!(f, "C3"),
            CpuFeaturesTemplate::T2 => write!(f, "T2"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_cpu_features_template() {
        assert_eq!(CpuFeaturesTemplate::C3.to_string(), "C3".to_string());
        assert_eq!(CpuFeaturesTemplate::T2.to_string(), "T2".to_string());
    }

    #[test]
    fn test_display_vm_config_error() {
        let expected_str = "The vCPU number is invalid! The vCPU number can only \
                            be 1 or an even number when hyperthreading is enabled.";
        assert_eq!(VmConfigError::InvalidVcpuCount.to_string(), expected_str);

        let expected_str = "The memory size (MiB) is invalid.";
        assert_eq!(VmConfigError::InvalidMemorySize.to_string(), expected_str);
    }
}

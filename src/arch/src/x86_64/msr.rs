// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug)]
/// MSR related errors.
pub enum Error {
    #[cfg(target_os = "linux")]
    /// Getting supported MSRs failed.
    GetSupportedModelSpecificRegisters(kvm_ioctls::Error),
    #[cfg(target_os = "linux")]
    /// Setting up MSRs failed.
    SetModelSpecificRegisters(kvm_ioctls::Error),
    /// Failed to set all MSRs.
    SetModelSpecificRegistersCount,
    #[cfg(target_os = "windows")]
    /// Setting up MSRs via WHP failed.
    SetMsrsWhp(whp::Error),
}

// Re-export platform-specific MSR setup functions.
#[cfg(target_os = "linux")]
pub use super::linux::msr::*;
#[cfg(target_os = "windows")]
pub use super::windows::msr::*;

/// IA32_MTRR_DEF_TYPE MSR: E (MTRRs enabled) flag, bit 11
pub const MTRR_ENABLE: u64 = 0x800;
/// Mem type WB
pub const MTRR_MEM_TYPE_WB: u64 = 0x6;

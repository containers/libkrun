// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::result;

use vm_memory::GuestMemoryMmap;

/// Errors thrown while setting aarch64 registers.
#[derive(Debug)]
pub enum Error {
    /// Failed to set core register (PC, PSTATE or general purpose ones).
    SetCoreRegister,
    /// Failed to get a system register.
    GetSysRegister,
}
type Result<T> = result::Result<T, Error>;

/// Configure core registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `cpu_id` - Index of current vcpu.
/// * `boot_ip` - Starting instruction pointer.
/// * `mem` - Reserved DRAM for current VM.
pub fn setup_regs(_cpu_id: u8, _boot_ip: u64, _mem: &GuestMemoryMmap) -> Result<()> {
    Ok(())
}

/// Read the MPIDR - Multiprocessor Affinity Register.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn read_mpidr() -> Result<u64> {
    Ok(0)
}

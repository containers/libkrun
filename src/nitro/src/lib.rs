// SPDX-License-Identifier: Apache-2.0

use std::fs::File;

/// Nitro Enclave data.
#[derive(Debug)]
pub struct NitroEnclave {
    /// Enclave image.
    pub image: File,
    /// Amount of RAM (in MiB).
    pub mem_size_mib: usize,
    /// Number of vCPUs.
    pub vcpus: u8,
}

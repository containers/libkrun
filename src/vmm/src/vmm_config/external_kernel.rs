// Copyright 2024, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub enum KernelFormat {
    // Raw image, ready to be loaded into the VM.
    Raw,
    // ELF image, need to locale sections be loaded.
    Elf,
    // Raw image compressed with GZIP, embedded into a PE file.
    PeGz,
    // ELF image compressed with BZIP2, embedded into an Image file.
    ImageBz2,
    // ELF image compressed with GZIP, embedded into an Image file.
    ImageGz,
    // ELF image compressed with ZSTD, embedded into an Image file.
    ImageZstd,
}

impl Default for KernelFormat {
    fn default() -> Self {
        Self::Raw
    }
}

/// Data structure holding the attributes read from the `libkrunfw` kernel config.
#[derive(Clone, Debug, Default)]
pub struct ExternalKernel {
    pub path: PathBuf,
    pub format: KernelFormat,
}

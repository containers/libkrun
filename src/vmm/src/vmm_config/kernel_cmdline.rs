// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter, Result};

pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=-1 panic_print=0 nomodule console=hvc0 \
                                          rootfstype=virtiofs rw quiet no-kvmapf";

/// Strongly typed data structure used to configure the boot source of the
/// microvm.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct KernelCmdlineConfig {
    pub cmdline: Vec<String>,
    pub args: Vec<String>,
}

/// Errors associated with actions on `KernelCmdlineConfig`.
#[derive(Debug)]
pub enum KernelCmdlineConfigError {
    /// The kernel command line is invalid.
    InvalidKernelCommandLine(String),
}

impl Display for KernelCmdlineConfigError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::KernelCmdlineConfigError::*;
        match *self {
            InvalidKernelCommandLine(ref e) => {
                write!(f, "The kernel command line is invalid: {}", e.as_str())
            }
        }
    }
}

impl std::error::Error for KernelCmdlineConfigError {}

// Copyright 2025, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub struct FirmwareConfig {
    pub path: PathBuf,
}

#[cfg(feature = "tdx")]
#[derive(Clone, Debug)]
pub enum TeeFirmwareType {
    TdShim,
}

#[cfg(feature = "tdx")]
#[derive(Clone, Debug)]
pub struct TeeFirmwareConfig {
    pub fw_type: TeeFirmwareType,
    pub path: PathBuf,
}

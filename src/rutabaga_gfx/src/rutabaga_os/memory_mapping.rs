// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::rutabaga_os::sys::platform::MemoryMapping as PlatformMapping;
use crate::rutabaga_os::SafeDescriptor;
use crate::rutabaga_utils::RutabagaMapping;
use crate::rutabaga_utils::RutabagaResult;

pub struct MemoryMapping {
    mapping: PlatformMapping,
}

impl MemoryMapping {
    pub fn from_safe_descriptor(
        descriptor: SafeDescriptor,
        size: usize,
        map_info: u32,
    ) -> RutabagaResult<MemoryMapping> {
        let mapping = PlatformMapping::from_safe_descriptor(descriptor, size, map_info)?;
        Ok(MemoryMapping { mapping })
    }

    pub fn as_rutabaga_mapping(&self) -> RutabagaMapping {
        RutabagaMapping {
            ptr: self.mapping.addr as u64,
            size: self.mapping.size as u64,
        }
    }
}

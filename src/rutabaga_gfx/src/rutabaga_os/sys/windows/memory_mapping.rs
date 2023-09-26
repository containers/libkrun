// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::c_void;

use crate::rutabaga_os::SafeDescriptor;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

/// Wraps an anonymous shared memory mapping in the current process. Provides
/// RAII semantics including munmap when no longer needed.
#[derive(Debug)]
pub struct MemoryMapping {
    pub addr: *mut c_void,
    pub size: usize,
}

impl MemoryMapping {
    pub fn from_safe_descriptor(
        _descriptor: SafeDescriptor,
        _size: usize,
        _map_info: u32,
    ) -> RutabagaResult<MemoryMapping> {
        Err(RutabagaError::Unsupported)
    }
}

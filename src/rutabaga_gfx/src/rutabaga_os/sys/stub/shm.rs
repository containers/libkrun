// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;

use crate::rutabaga_os::descriptor::AsRawDescriptor;
use crate::rutabaga_os::descriptor::IntoRawDescriptor;
use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

pub struct SharedMemory {
    size: u64,
}

impl SharedMemory {
    /// Creates a new shared memory file descriptor with zero size.
    pub fn new(_debug_name: &CStr, _size: u64) -> RutabagaResult<SharedMemory> {
        Err(RutabagaError::Unsupported)
    }

    /// Gets the size in bytes of the shared memory.
    ///
    /// The size returned here does not reflect changes by other interfaces or users of the shared
    /// memory file descriptor..
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl AsRawDescriptor for SharedMemory {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        unimplemented!()
    }
}

impl IntoRawDescriptor for SharedMemory {
    fn into_raw_descriptor(self) -> RawDescriptor {
        unimplemented!()
    }
}

/// Uses the system's page size in bytes to round the given value up to the nearest page boundary.
pub fn round_up_to_page_size(_v: u64) -> RutabagaResult<u64> {
    Err(RutabagaError::Unsupported)
}

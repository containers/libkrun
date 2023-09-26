// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;

use crate::rutabaga_os::descriptor::AsRawDescriptor;
use crate::rutabaga_os::descriptor::IntoRawDescriptor;
use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_os::SafeDescriptor;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

/// A shared memory file descriptor and its size.
pub struct SharedMemory {
    pub descriptor: SafeDescriptor,
    pub size: u64,
}

impl SharedMemory {
    /// Creates a new shared memory file mapping with zero size.
    pub fn new(_debug_name: &CStr, _size: u64) -> RutabagaResult<Self> {
        Err(RutabagaError::Unsupported)
    }

    /// Gets the size in bytes of the shared memory.
    ///
    /// The size returned here does not reflect changes by other interfaces or users of the shared
    /// memory file descriptor.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// USE THIS CAUTIOUSLY. The returned handle is not a file handle and cannot be
/// used as if it were one. It is a handle to a the associated file mapping object
/// and should only be used for memory-mapping the file view.
impl AsRawDescriptor for SharedMemory {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}

impl IntoRawDescriptor for SharedMemory {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.descriptor.into_raw_descriptor()
    }
}

pub fn round_up_to_page_size(_v: u64) -> RutabagaResult<u64> {
    Err(RutabagaError::Unsupported)
}

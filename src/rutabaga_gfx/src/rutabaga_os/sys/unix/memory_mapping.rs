// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::num::NonZeroUsize;

use libc::c_void;
use nix::sys::mman::mmap;
use nix::sys::mman::munmap;
use nix::sys::mman::MapFlags;
use nix::sys::mman::ProtFlags;

use crate::rutabaga_os::descriptor::AsRawDescriptor;
use crate::rutabaga_os::descriptor::SafeDescriptor;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

use crate::rutabaga_utils::RUTABAGA_MAP_ACCESS_MASK;
use crate::rutabaga_utils::RUTABAGA_MAP_ACCESS_READ;
use crate::rutabaga_utils::RUTABAGA_MAP_ACCESS_RW;
use crate::rutabaga_utils::RUTABAGA_MAP_ACCESS_WRITE;

/// Wraps an anonymous shared memory mapping in the current process. Provides
/// RAII semantics including munmap when no longer needed.
#[derive(Debug)]
pub struct MemoryMapping {
    pub addr: *mut c_void,
    pub size: usize,
}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        // This is safe because we mmap the area at addr ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            munmap(self.addr as *mut libc::c_void, self.size).unwrap();
        }
    }
}

impl MemoryMapping {
    pub fn from_safe_descriptor(
        descriptor: SafeDescriptor,
        size: usize,
        map_info: u32,
    ) -> RutabagaResult<MemoryMapping> {
        let non_zero_opt = NonZeroUsize::new(size);
        let prot = match map_info & RUTABAGA_MAP_ACCESS_MASK {
            RUTABAGA_MAP_ACCESS_READ => ProtFlags::PROT_READ,
            RUTABAGA_MAP_ACCESS_WRITE => ProtFlags::PROT_READ,
            RUTABAGA_MAP_ACCESS_RW => ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            _ => return Err(RutabagaError::SpecViolation("incorrect access flags")),
        };

        if let Some(non_zero_size) = non_zero_opt {
            let addr = unsafe {
                mmap(
                    None,
                    non_zero_size,
                    prot,
                    MapFlags::MAP_SHARED,
                    descriptor.as_raw_descriptor(),
                    0,
                )?
            };
            Ok(MemoryMapping { addr, size })
        } else {
            Err(RutabagaError::SpecViolation("zero size mapping"))
        }
    }
}

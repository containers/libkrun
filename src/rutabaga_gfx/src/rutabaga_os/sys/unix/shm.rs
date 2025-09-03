// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;
use std::ffi::CStr;
use std::os::unix::io::OwnedFd;

use libc::off_t;
use nix::sys::memfd::memfd_create;
use nix::sys::memfd::MFdFlags;
use nix::unistd::ftruncate;
use nix::unistd::sysconf;
use nix::unistd::SysconfVar;
use vmm_sys_util::align_upwards;

use crate::rutabaga_os::descriptor::AsRawDescriptor;
use crate::rutabaga_os::descriptor::IntoRawDescriptor;
use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

pub struct SharedMemory {
    fd: OwnedFd,
    size: u64,
}

impl SharedMemory {
    /// Creates a new shared memory file descriptor with zero size.
    ///
    /// If a name is given, it will appear in `/proc/self/fd/<shm fd>` for the purposes of
    /// debugging. The name does not need to be unique.
    ///
    /// The file descriptor is opened with the close on exec flag and allows memfd sealing.
    pub fn new(debug_name: &CStr, size: u64) -> RutabagaResult<SharedMemory> {
        // Nix will transition to owned fd in future releases, do it locally here.
        let fd = memfd_create(
            debug_name,
            MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
        )?;

        let size_off_t: off_t = size.try_into()?;
        ftruncate(&fd, size_off_t)?;

        Ok(SharedMemory { fd, size })
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
        self.fd.as_raw_descriptor()
    }
}

impl IntoRawDescriptor for SharedMemory {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.fd.into_raw_descriptor()
    }
}

/// Uses the system's page size in bytes to round the given value up to the nearest page boundary.
pub fn round_up_to_page_size(v: u64) -> RutabagaResult<u64> {
    let page_size_opt = sysconf(SysconfVar::PAGE_SIZE)?;
    if let Some(page_size) = page_size_opt {
        let aligned_size = align_upwards!(v, page_size as u64);
        Ok(aligned_size)
    } else {
        Err(RutabagaError::SpecViolation("no page size"))
    }
}

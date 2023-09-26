// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(feature = "minigbm")]

use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_uint;
#[cfg(target_pointer_width = "64")]
use std::os::raw::c_ulong;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr::null_mut;

use nix::ioctl_readwrite;

use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

// Consistent with __kernel_size_t in include/uapi/asm-generic/posix_types.h.
#[cfg(not(target_pointer_width = "64"))]
#[allow(non_camel_case_types)]
type __kernel_size_t = c_uint;
#[cfg(target_pointer_width = "64")]
#[allow(non_camel_case_types)]
type __kernel_size_t = c_ulong;

const DRM_IOCTL_BASE: c_uint = 0x64;
const DRM_IOCTL_VERSION: c_uint = 0x00;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct drm_version {
    version_major: c_int,
    version_minor: c_int,
    version_patchlevel: c_int,
    name_len: __kernel_size_t,
    name: *mut c_char,
    date_len: __kernel_size_t,
    date: *mut c_char,
    desc_len: __kernel_size_t,
    desc: *mut c_char,
}

ioctl_readwrite!(
    drm_get_version,
    DRM_IOCTL_BASE,
    DRM_IOCTL_VERSION,
    drm_version
);

fn get_drm_device_name(fd: &File) -> RutabagaResult<String> {
    let mut version = drm_version {
        version_major: 0,
        version_minor: 0,
        version_patchlevel: 0,
        name_len: 0,
        name: null_mut(),
        date_len: 0,
        date: null_mut(),
        desc_len: 0,
        desc: null_mut(),
    };

    // Get the length of the device name.
    unsafe {
        drm_get_version(fd.as_raw_fd(), &mut version)?;
    }

    // Enough bytes to hold the device name and terminating null character.
    let mut name_bytes: Vec<u8> = vec![0; (version.name_len + 1) as usize];
    let mut version = drm_version {
        version_major: 0,
        version_minor: 0,
        version_patchlevel: 0,
        name_len: name_bytes.len() as __kernel_size_t,
        name: name_bytes.as_mut_ptr() as *mut c_char,
        date_len: 0,
        date: null_mut(),
        desc_len: 0,
        desc: null_mut(),
    };

    // Safe as no more than name_len + 1 bytes will be written to name.
    unsafe {
        drm_get_version(fd.as_raw_fd(), &mut version)?;
    }

    CString::new(&name_bytes[..(version.name_len as usize)])?
        .into_string()
        .map_err(|_| RutabagaError::SpecViolation("couldn't convert string"))
}

/// Returns a `fd` for an opened rendernode device, while filtering out specified
/// undesired drivers.
pub fn open_device(undesired: &[&str]) -> RutabagaResult<File> {
    const DRM_DIR_NAME: &str = "/dev/dri";
    const DRM_MAX_MINOR: u32 = 15;
    const RENDER_NODE_START: u32 = 128;

    for n in RENDER_NODE_START..=RENDER_NODE_START + DRM_MAX_MINOR {
        let path = Path::new(DRM_DIR_NAME).join(format!("renderD{}", n));

        if let Ok(fd) = OpenOptions::new().read(true).write(true).open(path) {
            if let Ok(name) = get_drm_device_name(&fd) {
                if !undesired.iter().any(|item| *item == name) {
                    return Ok(fd);
                }
            }
        }
    }

    Err(RutabagaError::SpecViolation("no DRM rendernode opened"))
}

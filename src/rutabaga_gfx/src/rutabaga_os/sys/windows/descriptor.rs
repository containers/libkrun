// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::fs::File;
use std::io;
use std::marker::Send;
use std::marker::Sync;
use std::ops::Drop;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::IntoRawHandle;
use std::os::windows::io::RawHandle;

use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::TRUE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::DuplicateHandle;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::DUPLICATE_SAME_ACCESS;

use crate::rutabaga_os::descriptor::AsRawDescriptor;
use crate::rutabaga_os::descriptor::Descriptor;
use crate::rutabaga_os::descriptor::FromRawDescriptor;
use crate::rutabaga_os::descriptor::IntoRawDescriptor;
use crate::rutabaga_os::descriptor::SafeDescriptor;

type Error = std::io::Error;
type Result<T> = std::result::Result<T, Error>;

pub type RawDescriptor = RawHandle;

impl Drop for SafeDescriptor {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.descriptor) };
    }
}

impl AsRawHandle for SafeDescriptor {
    fn as_raw_handle(&self) -> RawHandle {
        self.as_raw_descriptor()
    }
}

pub fn duplicate_handle_from_source_process(
    source_process_handle: RawHandle,
    hndl: RawHandle,
    target_process_handle: RawHandle,
) -> io::Result<RawHandle> {
    // Safe because:
    // 1. We are checking the return code
    // 2. new_handle_ptr points to a valid location on the stack
    // 3. Caller guarantees hndl is a real valid handle.
    unsafe {
        let mut new_handle: RawHandle = std::ptr::null_mut();
        let success_flag = DuplicateHandle(
            /* hSourceProcessHandle= */ source_process_handle,
            /* hSourceHandle= */ hndl,
            /* hTargetProcessHandle= */ target_process_handle,
            /* lpTargetHandle= */ &mut new_handle,
            /* dwDesiredAccess= */ 0,
            /* bInheritHandle= */ TRUE,
            /* dwOptions= */ DUPLICATE_SAME_ACCESS,
        );

        if success_flag == FALSE {
            Err(io::Error::last_os_error())
        } else {
            Ok(new_handle)
        }
    }
}

fn duplicate_handle_with_target_handle(
    hndl: RawHandle,
    target_process_handle: RawHandle,
) -> io::Result<RawHandle> {
    // Safe because `GetCurrentProcess` just gets the current process handle.
    duplicate_handle_from_source_process(
        unsafe { GetCurrentProcess() },
        hndl,
        target_process_handle,
    )
}

pub fn duplicate_handle(hndl: RawHandle) -> io::Result<RawHandle> {
    // Safe because `GetCurrentProcess` just gets the current process handle.
    duplicate_handle_with_target_handle(hndl, unsafe { GetCurrentProcess() })
}

impl TryFrom<&dyn AsRawHandle> for SafeDescriptor {
    type Error = std::io::Error;

    fn try_from(handle: &dyn AsRawHandle) -> std::result::Result<Self, Self::Error> {
        Ok(SafeDescriptor {
            descriptor: duplicate_handle(handle.as_raw_handle())?,
        })
    }
}

impl SafeDescriptor {
    /// Clones this descriptor, internally creating a new descriptor. The new SafeDescriptor will
    /// share the same underlying count within the kernel.
    pub fn try_clone(&self) -> Result<SafeDescriptor> {
        // Safe because `duplicate_handle` will return a valid handle, or at the very least error
        // out.
        Ok(unsafe { SafeDescriptor::from_raw_descriptor(duplicate_handle(self.descriptor)?) })
    }
}

// On Windows, RawHandles are represented by raw pointers but are not used as such in
// rust code, and are therefore safe to send between threads.
unsafe impl Send for SafeDescriptor {}
unsafe impl Sync for SafeDescriptor {}

// On Windows, RawHandles are represented by raw pointers but are opaque to the
// userspace and cannot be derefenced by rust code, and are therefore safe to
// send between threads.
unsafe impl Send for Descriptor {}
unsafe impl Sync for Descriptor {}

macro_rules! AsRawDescriptor {
    ($name:ident) => {
        impl AsRawDescriptor for $name {
            fn as_raw_descriptor(&self) -> RawDescriptor {
                return self.as_raw_handle();
            }
        }
    };
}

macro_rules! FromRawDescriptor {
    ($name:ident) => {
        impl FromRawDescriptor for $name {
            unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
                return $name::from_raw_handle(descriptor);
            }
        }
    };
}

macro_rules! IntoRawDescriptor {
    ($name:ident) => {
        impl IntoRawDescriptor for $name {
            fn into_raw_descriptor(self) -> RawDescriptor {
                return self.into_raw_handle();
            }
        }
    };
}

// Implementations for File. This enables the File-type to use the cross-platform
// RawDescriptor, but does not mean File should be used as a generic
// descriptor container. That should go to either SafeDescriptor or another more
// relevant container type.
// TODO(b/148971445): Ensure there are no usages of File that aren't actually files.
AsRawDescriptor!(File);
FromRawDescriptor!(File);
IntoRawDescriptor!(File);

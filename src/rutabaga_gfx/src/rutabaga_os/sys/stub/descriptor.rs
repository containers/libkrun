// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::OwnedFd;
use std::os::unix::io::RawFd;

use crate::rutabaga_os::descriptor::AsRawDescriptor;
use crate::rutabaga_os::descriptor::Descriptor;
use crate::rutabaga_os::descriptor::FromRawDescriptor;
use crate::rutabaga_os::descriptor::IntoRawDescriptor;
use crate::rutabaga_os::descriptor::SafeDescriptor;

type Error = std::io::Error;
type Result<T> = std::result::Result<T, Error>;

pub type RawDescriptor = RawFd;

/// Clones `fd`, returning a new file descriptor that refers to the same open file description as
/// `fd`. The cloned fd will have the `FD_CLOEXEC` flag set but will not share any other file
/// descriptor flags with `fd`.
fn clone_fd(fd: &dyn AsRawFd) -> Result<RawFd> {
    // Safe because this doesn't modify any memory and we check the return value.
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if ret < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(ret)
    }
}

impl Drop for SafeDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.descriptor) };
    }
}

impl AsRawFd for SafeDescriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.as_raw_descriptor()
    }
}

impl TryFrom<&dyn AsRawFd> for SafeDescriptor {
    type Error = std::io::Error;

    fn try_from(fd: &dyn AsRawFd) -> Result<Self> {
        Ok(SafeDescriptor {
            descriptor: clone_fd(fd)?,
        })
    }
}

impl SafeDescriptor {
    /// Clones this descriptor, internally creating a new descriptor. The new SafeDescriptor will
    /// share the same underlying count within the kernel.
    pub fn try_clone(&self) -> Result<SafeDescriptor> {
        // Safe because this doesn't modify any memory and we check the return value.
        let descriptor = unsafe { libc::fcntl(self.descriptor, libc::F_DUPFD_CLOEXEC, 0) };
        if descriptor < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(SafeDescriptor { descriptor })
        }
    }
}

impl From<SafeDescriptor> for File {
    fn from(s: SafeDescriptor) -> File {
        // Safe because we own the SafeDescriptor at this point.
        unsafe { File::from_raw_fd(s.into_raw_descriptor()) }
    }
}

// AsRawFd for interoperability with interfaces that require it. Within crosvm,
// always use AsRawDescriptor when possible.
impl AsRawFd for Descriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

macro_rules! AsRawDescriptor {
    ($name:ident) => {
        impl AsRawDescriptor for $name {
            fn as_raw_descriptor(&self) -> RawDescriptor {
                self.as_raw_fd()
            }
        }
    };
}

macro_rules! FromRawDescriptor {
    ($name:ident) => {
        impl FromRawDescriptor for $name {
            unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
                $name::from_raw_fd(descriptor)
            }
        }
    };
}

macro_rules! IntoRawDescriptor {
    ($name:ident) => {
        impl IntoRawDescriptor for $name {
            fn into_raw_descriptor(self) -> RawDescriptor {
                self.into_raw_fd()
            }
        }
    };
}

// Implementations for File. This enables the File-type to use
// RawDescriptor, but does not mean File should be used as a generic
// descriptor container. That should go to either SafeDescriptor or another more
// relevant container type.
AsRawDescriptor!(File);
FromRawDescriptor!(File);
IntoRawDescriptor!(File);
AsRawDescriptor!(OwnedFd);
FromRawDescriptor!(OwnedFd);
IntoRawDescriptor!(OwnedFd);

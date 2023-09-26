// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;

use crate::rutabaga_os::descriptor::AsRawDescriptor;
use crate::rutabaga_os::descriptor::FromRawDescriptor;
use crate::rutabaga_os::descriptor::IntoRawDescriptor;
use crate::rutabaga_os::descriptor::SafeDescriptor;

type Error = std::io::Error;
type Result<T> = std::result::Result<T, Error>;

pub type RawDescriptor = i64;

impl Drop for SafeDescriptor {
    fn drop(&mut self) {
        unimplemented!()
    }
}

impl SafeDescriptor {
    /// Clones this descriptor, internally creating a new descriptor. The new SafeDescriptor will
    /// share the same underlying count within the kernel.
    pub fn try_clone(&self) -> Result<SafeDescriptor> {
        Err(Error::last_os_error())
    }
}

impl From<SafeDescriptor> for File {
    fn from(_s: SafeDescriptor) -> File {
        // Safe because we own the SafeDescriptor at this point.
        unimplemented!()
    }
}

macro_rules! AsRawDescriptor {
    ($name:ident) => {
        impl AsRawDescriptor for $name {
            fn as_raw_descriptor(&self) -> RawDescriptor {
                unimplemented!()
            }
        }
    };
}

macro_rules! FromRawDescriptor {
    ($name:ident) => {
        impl FromRawDescriptor for $name {
            unsafe fn from_raw_descriptor(_descriptor: RawDescriptor) -> Self {
                unimplemented!()
            }
        }
    };
}

macro_rules! IntoRawDescriptor {
    ($name:ident) => {
        impl IntoRawDescriptor for $name {
            fn into_raw_descriptor(self) -> RawDescriptor {
                unimplemented!()
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

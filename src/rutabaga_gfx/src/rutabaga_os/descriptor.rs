// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::mem;
use std::mem::ManuallyDrop;

use crate::rutabaga_os::RawDescriptor;

/// Wraps a RawDescriptor and safely closes it when self falls out of scope.
pub struct SafeDescriptor {
    pub(crate) descriptor: RawDescriptor,
}

/// Trait for forfeiting ownership of the current raw descriptor, and returning the raw descriptor
pub trait IntoRawDescriptor {
    fn into_raw_descriptor(self) -> RawDescriptor;
}

/// Trait for returning the underlying raw descriptor, without giving up ownership of the
/// descriptor.
pub trait AsRawDescriptor {
    /// Returns the underlying raw descriptor.
    ///
    /// Since the descriptor is still owned by the provider, callers should not assume that it will
    /// remain open for longer than the immediate call of this method. In particular, it is a
    /// dangerous practice to store the result of this method for future use: instead, it should be
    /// used to e.g. obtain a raw descriptor that is immediately passed to a system call.
    ///
    /// If you need to use the descriptor for a longer time (and particularly if you cannot reliably
    /// track the lifetime of the providing object), you should probably consider using
    /// [`SafeDescriptor`] (possibly along with [`trait@IntoRawDescriptor`]) to get full ownership
    /// over a descriptor pointing to the same resource.
    fn as_raw_descriptor(&self) -> RawDescriptor;
}

/// A trait similar to `AsRawDescriptor` but supports an arbitrary number of descriptors.
pub trait AsRawDescriptors {
    /// Returns the underlying raw descriptors.
    ///
    /// Please refer to the documentation of [`AsRawDescriptor::as_raw_descriptor`] for limitations
    /// and recommended use.
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor>;
}

pub trait FromRawDescriptor {
    /// # Safety
    /// Safe only if the caller ensures nothing has access to the descriptor after passing it to
    /// `from_raw_descriptor`
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self;
}

impl AsRawDescriptor for SafeDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor
    }
}

impl<T> AsRawDescriptors for T
where
    T: AsRawDescriptor,
{
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![self.as_raw_descriptor()]
    }
}

impl IntoRawDescriptor for SafeDescriptor {
    fn into_raw_descriptor(self) -> RawDescriptor {
        let descriptor = self.descriptor;
        mem::forget(self);
        descriptor
    }
}

impl FromRawDescriptor for SafeDescriptor {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        SafeDescriptor { descriptor }
    }
}

impl TryFrom<&dyn AsRawDescriptor> for SafeDescriptor {
    type Error = std::io::Error;

    /// Clones the underlying descriptor (handle), internally creating a new descriptor.
    ///
    /// WARNING: Windows does NOT support cloning/duplicating all types of handles. DO NOT use this
    /// function on IO completion ports, sockets, or pseudo-handles (except those from
    /// GetCurrentProcess or GetCurrentThread). See
    /// <https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle>
    /// for further details.
    ///
    /// TODO(b/191800567): this API has sharp edges on Windows. We should evaluate making some
    /// adjustments to smooth those edges.
    fn try_from(rd: &dyn AsRawDescriptor) -> std::result::Result<Self, Self::Error> {
        // Safe because the underlying raw descriptor is guaranteed valid by rd's existence.
        //
        // Note that we are cloning the underlying raw descriptor since we have no guarantee of
        // its existence after this function returns.
        let rd_as_safe_desc = ManuallyDrop::new(unsafe {
            SafeDescriptor::from_raw_descriptor(rd.as_raw_descriptor())
        });

        // We have to clone rd because we have no guarantee ownership was transferred (rd is
        // borrowed).
        rd_as_safe_desc
            .try_clone()
            .map_err(|_| Self::Error::last_os_error())
    }
}

impl From<File> for SafeDescriptor {
    fn from(f: File) -> SafeDescriptor {
        // Safe because we own the File at this point.
        unsafe { SafeDescriptor::from_raw_descriptor(f.into_raw_descriptor()) }
    }
}

/// For use cases where a simple wrapper around a [`RawDescriptor`] is needed, in order to e.g.
/// implement [`trait@AsRawDescriptor`].
///
/// This is a simply a wrapper and does not manage the lifetime of the descriptor. As such it is the
/// responsibility of the user to ensure that the wrapped descriptor will not be closed for as long
/// as the `Descriptor` is alive.
///
/// Most use-cases should prefer [`SafeDescriptor`] or implementing and using
/// [`trait@AsRawDescriptor`] on the type providing the descriptor. Using this wrapper usually means
/// something can be improved in your code.
///
/// Valid uses of this struct include:
/// * You only have a valid [`RawDescriptor`] and need to pass something that implements
///   [`trait@AsRawDescriptor`] to a function,
/// * You need to serialize a [`RawDescriptor`],
/// * You need [`trait@Send`] or [`trait@Sync`] for your descriptor and properly handle the case
///   where your descriptor gets closed.
///
/// Note that with the exception of the last use-case (which requires proper error checking against
/// the descriptor being closed), the `Descriptor` instance would be very short-lived.
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Descriptor(pub RawDescriptor);
impl AsRawDescriptor for Descriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0
    }
}

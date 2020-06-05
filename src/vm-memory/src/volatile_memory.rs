// Portions Copyright 2019 Red Hat, Inc.
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRT-PARTY file.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Types for volatile access to memory.
//!
//! Two of the core rules for safe rust is no data races and no aliased mutable references.
//! `VolatileRef` and `VolatileSlice`, along with types that produce those which implement
//! `VolatileMemory`, allow us to sidestep that rule by wrapping pointers that absolutely have to be
//! accessed volatile. Some systems really do need to operate on shared memory and can't have the
//! compiler reordering or eliding access because it has no visibility into what other systems are
//! doing with that hunk of memory.
//!
//! For the purposes of maintaining safety, volatile memory has some rules of its own:
//! 1. No references or slices to volatile memory (`&` or `&mut`).
//! 2. Access should always been done with a volatile read or write.
//! The First rule is because having references of any kind to memory considered volatile would
//! violate pointer aliasing. The second is because unvolatile accesses are inherently undefined if
//! done concurrently without synchronization. With volatile access we know that the compiler has
//! not reordered or elided the access.

use std::cmp::min;
use std::convert::TryFrom;
use std::error;
use std::fmt;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::mem::{align_of, size_of};
use std::ptr::copy;
use std::ptr::{read_volatile, write_volatile};
use std::result;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::usize;

use crate::{ByteValued, Bytes};

/// `VolatileMemory` related errors.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    /// `addr` is out of bounds of the volatile memory slice.
    OutOfBounds { addr: usize },
    /// Taking a slice at `base` with `offset` would overflow `usize`.
    Overflow { base: usize, offset: usize },
    /// Taking a slice whose size overflows `usize`.
    TooBig { nelements: usize, size: usize },
    /// Trying to obtain a misaligned reference.
    Misaligned { addr: usize, alignment: usize },
    /// Writing to memory failed
    IOError(io::Error),
    /// Incomplete read or write
    PartialBuffer { expected: usize, completed: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::OutOfBounds { addr } => write!(f, "address 0x{:x} is out of bounds", addr),
            Error::Overflow { base, offset } => write!(
                f,
                "address 0x{:x} offset by 0x{:x} would overflow",
                base, offset
            ),
            Error::TooBig { nelements, size } => write!(
                f,
                "{:?} elements of size {:?} would overflow a usize",
                nelements, size
            ),
            Error::Misaligned { addr, alignment } => {
                write!(f, "address 0x{:x} is not aligned to {:?}", addr, alignment)
            }
            Error::IOError(error) => write!(f, "{}", error),
            Error::PartialBuffer {
                expected,
                completed,
            } => write!(
                f,
                "only used {} bytes in {} long buffer",
                completed, expected
            ),
        }
    }
}

impl error::Error for Error {}

/// Result of volatile memory operations.
pub type Result<T> = result::Result<T, Error>;

/// Convenience function for computing `base + offset`.
///
/// # Errors
///
/// Returns [`Err(Error::Overflow)`](enum.Error.html#variant.Overflow) in case `base + offset`
/// exceeds `usize::MAX`.
///
/// # Examples
///
/// ```
/// # use vm_memory::volatile_memory::*;
/// # fn get_slice(offset: usize, count: usize) -> Result<()> {
///   let mem_end = compute_offset(offset, count)?;
///   if mem_end > 100 {
///       return Err(Error::OutOfBounds{addr: mem_end});
///   }
/// # Ok(())
/// # }
/// ```
pub fn compute_offset(base: usize, offset: usize) -> Result<usize> {
    match base.checked_add(offset) {
        None => Err(Error::Overflow { base, offset }),
        Some(m) => Ok(m),
    }
}

/// Types that can be read safely from a [`VolatileSlice`](struct.VolatileSlice.html).
///
/// Objects that implement this trait must consist exclusively of atomic types
/// from [`std::sync::atomic`](https://doc.rust-lang.org/std/sync/atomic/), except for
/// [`AtomicPtr<T>`](https://doc.rust-lang.org/std/sync/atomic/struct.AtomicPtr.html).
pub unsafe trait AtomicValued: Sync + Send {}

// also conditionalize on #[cfg(target_has_atomic) when it is stabilized
#[cfg(feature = "integer-atomics")]
unsafe impl AtomicValued for std::sync::atomic::AtomicBool {}
#[cfg(feature = "integer-atomics")]
unsafe impl AtomicValued for std::sync::atomic::AtomicI8 {}
#[cfg(feature = "integer-atomics")]
unsafe impl AtomicValued for std::sync::atomic::AtomicI16 {}
#[cfg(feature = "integer-atomics")]
unsafe impl AtomicValued for std::sync::atomic::AtomicI32 {}
#[cfg(feature = "integer-atomics")]
unsafe impl AtomicValued for std::sync::atomic::AtomicI64 {}
unsafe impl AtomicValued for std::sync::atomic::AtomicIsize {}
#[cfg(feature = "integer-atomics")]
unsafe impl AtomicValued for std::sync::atomic::AtomicU8 {}
#[cfg(feature = "integer-atomics")]
unsafe impl AtomicValued for std::sync::atomic::AtomicU16 {}
#[cfg(feature = "integer-atomics")]
unsafe impl AtomicValued for std::sync::atomic::AtomicU32 {}
#[cfg(feature = "integer-atomics")]
unsafe impl AtomicValued for std::sync::atomic::AtomicU64 {}
unsafe impl AtomicValued for std::sync::atomic::AtomicUsize {}

/// Types that support raw volatile access to their data.
pub trait VolatileMemory {
    /// Gets the size of this slice.
    fn len(&self) -> usize;

    /// Check whether the region is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a [`VolatileSlice`](struct.VolatileSlice.html) of `count` bytes starting at
    /// `offset`.
    fn get_slice(&self, offset: usize, count: usize) -> Result<VolatileSlice>;

    /// Gets a slice of memory for the entire region that supports volatile access.
    fn as_volatile_slice(&self) -> VolatileSlice {
        self.get_slice(0, self.len()).unwrap()
    }

    /// Gets a `VolatileRef` at `offset`.
    fn get_ref<T: ByteValued>(&self, offset: usize) -> Result<VolatileRef<T>> {
        let slice = self.get_slice(offset, size_of::<T>())?;
        unsafe {
            // This is safe because the pointer is range-checked by get_slice, and
            // the lifetime is the same as self.
            Ok(VolatileRef::<T>::new(slice.addr))
        }
    }

    /// Returns a [`VolatileArrayRef`](struct.VolatileArrayRef.html) of `n` elements starting at
    /// `offset`.
    fn get_array_ref<T: ByteValued>(&self, offset: usize, n: usize) -> Result<VolatileArrayRef<T>> {
        // Use isize to avoid problems with ptr::offset and ptr::add down the line.
        let nbytes = isize::try_from(n)
            .ok()
            .and_then(|n| n.checked_mul(size_of::<T>() as isize))
            .ok_or(Error::TooBig {
                nelements: n,
                size: size_of::<T>(),
            })?;
        let slice = self.get_slice(offset, nbytes as usize)?;
        unsafe {
            // This is safe because the pointer is range-checked by get_slice, and
            // the lifetime is the same as self.
            Ok(VolatileArrayRef::<T>::new(slice.addr, n))
        }
    }

    /// Returns a reference to an instance of `T` at `offset`.
    ///
    /// # Safety
    /// To use this safely, the caller must guarantee that there are no other
    /// users of the given chunk of memory for the lifetime of the result.
    ///
    /// # Errors
    ///
    /// If the resulting pointer is not aligned, this method will return an
    /// [`Error`](enum.Error.html).
    unsafe fn aligned_as_ref<T: ByteValued>(&self, offset: usize) -> Result<&T> {
        let slice = self.get_slice(offset, size_of::<T>())?;
        slice.check_alignment(align_of::<T>())?;
        Ok(&*(slice.addr as *const T))
    }

    /// Returns a mutable reference to an instance of `T` at `offset`.
    ///
    /// # Safety
    ///
    /// To use this safely, the caller must guarantee that there are no other
    /// users of the given chunk of memory for the lifetime of the result.
    ///
    /// # Errors
    ///
    /// If the resulting pointer is not aligned, this method will return an
    /// [`Error`](enum.Error.html).
    unsafe fn aligned_as_mut<T: ByteValued>(&self, offset: usize) -> Result<&mut T> {
        let slice = self.get_slice(offset, size_of::<T>())?;
        slice.check_alignment(align_of::<T>())?;
        Ok(&mut *(slice.addr as *mut T))
    }

    /// Returns a reference to an instance of `T` at `offset`.
    ///
    /// # Errors
    ///
    /// If the resulting pointer is not aligned, this method will return an
    /// [`Error`](enum.Error.html).
    fn get_atomic_ref<T: AtomicValued>(&self, offset: usize) -> Result<&T> {
        let slice = self.get_slice(offset, size_of::<T>())?;
        slice.check_alignment(align_of::<T>())?;

        unsafe {
            // This is safe because the pointer is range-checked by get_slice, and
            // the lifetime is the same as self.
            Ok(&*(slice.addr as *const T))
        }
    }

    /// Returns the sum of `base` and `offset` if the resulting address is valid.
    fn compute_end_offset(&self, base: usize, offset: usize) -> Result<usize> {
        let mem_end = compute_offset(base, offset)?;
        if mem_end > self.len() {
            return Err(Error::OutOfBounds { addr: mem_end });
        }
        Ok(mem_end)
    }
}

impl<'a> VolatileMemory for &'a mut [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn get_slice(&self, offset: usize, count: usize) -> Result<VolatileSlice> {
        let _ = self.compute_end_offset(offset, count)?;
        unsafe {
            // This is safe because the pointer is range-checked by compute_end_offset, and
            // the lifetime is the same as the original slice.
            Ok(VolatileSlice::new(
                (self.as_ptr() as usize + offset) as *mut _,
                count,
            ))
        }
    }
}

#[repr(C, packed)]
struct Packed<T>(T);

/// A slice of raw memory that supports volatile access.
#[derive(Copy, Clone, Debug)]
pub struct VolatileSlice<'a> {
    addr: *mut u8,
    size: usize,
    phantom: PhantomData<&'a u8>,
}

impl<'a> VolatileSlice<'a> {
    /// Creates a slice of raw memory that must support volatile access.
    ///
    /// # Safety
    ///
    /// To use this safely, the caller must guarantee that the memory at `addr` is `size` bytes long
    /// and is available for the duration of the lifetime of the new `VolatileSlice`. The caller
    /// must also guarantee that all other users of the given chunk of memory are using volatile
    /// accesses.
    pub unsafe fn new(addr: *mut u8, size: usize) -> VolatileSlice<'a> {
        VolatileSlice {
            addr,
            size,
            phantom: PhantomData,
        }
    }

    /// Returns a pointer to the beginning of the slice.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Gets the size of this slice.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Checks if the slice is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Returns a subslice of this [`VolatileSlice`](struct.VolatileSlice.html) starting at
    /// `offset`.
    ///
    /// The returned subslice is a copy of this slice with the address increased by `count` bytes
    /// and the size reduced by `count` bytes.
    pub fn offset(self, count: usize) -> Result<VolatileSlice<'a>> {
        let new_addr = (self.addr as usize)
            .checked_add(count)
            .ok_or(Error::Overflow {
                base: self.addr as usize,
                offset: count,
            })?;
        let new_size = self
            .size
            .checked_sub(count)
            .ok_or(Error::OutOfBounds { addr: new_addr })?;
        unsafe {
            // Safe because the memory has the same lifetime and points to a subset of the
            // memory of the original slice.
            Ok(VolatileSlice::new(new_addr as *mut u8, new_size))
        }
    }

    /// Copies as many elements of type `T` as possible from this slice to `buf`.
    ///
    /// Copies `self.len()` or `buf.len()` times the size of `T` bytes, whichever is smaller,
    /// to `buf`. The copy happens from smallest to largest address in `T` sized chunks
    /// using volatile reads.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # use vm_memory::VolatileMemory;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let mem_ref = &mut mem[..];
    /// let vslice = mem_ref.get_slice(0, 32).map_err(|_| ())?;
    /// let mut buf = [5u8; 16];
    /// vslice.copy_to(&mut buf[..]);
    /// for v in &buf[..] {
    ///     assert_eq!(buf[0], 0);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_to<T>(&self, buf: &mut [T]) -> usize
    where
        T: ByteValued,
    {
        let count = self.size / size_of::<T>();
        let source = self.get_array_ref::<T>(0, count).unwrap();
        source.copy_to(buf)
    }

    /// Copies as many bytes as possible from this slice to the provided `slice`.
    ///
    /// The copies happen in an undefined order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use vm_memory::VolatileMemory;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let mem_ref = &mut mem[..];
    /// let vslice = mem_ref.get_slice(0, 32).map_err(|_| ())?;
    /// vslice.copy_to_volatile_slice(vslice.get_slice(16, 16).map_err(|_| ())?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_to_volatile_slice(&self, slice: VolatileSlice) {
        unsafe {
            // Safe because the pointers are range-checked when the slices
            // are created, and they never escape the VolatileSlices.
            // FIXME: ... however, is it really okay to mix non-volatile
            // operations such as copy with read_volatile and write_volatile?
            copy(self.addr, slice.addr, min(self.size, slice.size));
        }
    }

    /// Copies as many elements of type `T` as possible from `buf` to this slice.
    ///
    /// The copy happens from smallest to largest address in `T` sized chunks using volatile writes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # use vm_memory::VolatileMemory;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let mem_ref = &mut mem[..];
    /// let vslice = mem_ref.get_slice(0, 32).map_err(|_| ())?;
    /// let buf = [5u8; 64];
    /// vslice.copy_from(&buf[..]);
    /// for i in 0..4 {
    ///     assert_eq!(vslice.get_ref::<u32>(i * 4).map_err(|_| ())?.load(), 0x05050505);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_from<T>(&self, buf: &[T])
    where
        T: ByteValued,
    {
        let count = self.size / size_of::<T>();
        let dest = self.get_array_ref::<T>(0, count).unwrap();
        dest.copy_from(buf)
    }

    /// Returns a slice corresponding to the data in the underlying memory.
    ///
    /// # Safety
    ///
    /// This function is private and only used for the read/write functions. It is not valid in
    /// general to take slices of volatile memory.
    unsafe fn as_slice(&self) -> &[u8] {
        from_raw_parts(self.addr, self.size)
    }

    /// Returns a mutable slice corresponding to the data in the underlying memory.
    ///
    /// # Safety
    ///
    /// This function is private and only used for the read/write functions. It is not valid in
    /// general to take slices of volatile memory.
    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self) -> &mut [u8] {
        from_raw_parts_mut(self.addr, self.size)
    }

    /// Checks if the current slice is aligned at `alignment` bytes.
    fn check_alignment(&self, alignment: usize) -> Result<()> {
        // Check that the desired alignment is a power of two.
        debug_assert!((alignment & (alignment - 1)) == 0);
        if ((self.addr as usize) & (alignment - 1)) != 0 {
            return Err(Error::Misaligned {
                addr: self.addr as usize,
                alignment,
            });
        }
        Ok(())
    }
}

impl Bytes<usize> for VolatileSlice<'_> {
    type E = Error;

    /// # Examples
    /// * Write a slice of size 5 at offset 1020 of a 1024-byte VolatileSlice.
    ///
    /// ```
    /// #   use vm_memory::{Bytes, VolatileMemory};
    /// #   let mut mem = [0u8; 1024];
    /// #   let mut mem_ref = &mut mem[..];
    /// #   let vslice = mem_ref.as_volatile_slice();
    ///     let res = vslice.write(&[1,2,3,4,5], 1020);
    ///     assert!(res.is_ok());
    ///     assert_eq!(res.unwrap(), 4);
    /// ```
    fn write(&self, buf: &[u8], addr: usize) -> Result<usize> {
        if addr >= self.size {
            return Err(Error::OutOfBounds { addr });
        }
        unsafe {
            // Guest memory can't strictly be modeled as a slice because it is
            // volatile.  Writing to it with what compiles down to a memcpy
            // won't hurt anything as long as we get the bounds checks right.
            let mut slice: &mut [u8] = &mut self.as_mut_slice()[addr..];
            slice.write(buf).map_err(Error::IOError)
        }
    }

    /// # Examples
    /// * Read a slice of size 16 at offset 1010 of a 1024-byte VolatileSlice.
    ///
    /// ```
    /// #   use vm_memory::{Bytes, VolatileMemory};
    /// #   let mut mem = [0u8; 1024];
    /// #   let mut mem_ref = &mut mem[..];
    /// #   let vslice = mem_ref.as_volatile_slice();
    ///     let buf = &mut [0u8; 16];
    ///     let res = vslice.read(buf, 1010);
    ///     assert!(res.is_ok());
    ///     assert_eq!(res.unwrap(), 14);
    /// ```
    fn read(&self, mut buf: &mut [u8], addr: usize) -> Result<usize> {
        if addr >= self.size {
            return Err(Error::OutOfBounds { addr });
        }
        unsafe {
            // Guest memory can't strictly be modeled as a slice because it is
            // volatile.  Writing to it with what compiles down to a memcpy
            // won't hurt anything as long as we get the bounds checks right.
            let slice: &[u8] = &self.as_slice()[addr..];
            buf.write(slice).map_err(Error::IOError)
        }
    }

    /// # Examples
    /// * Write a slice at offset 256.
    ///
    /// ```
    /// #   use vm_memory::{Bytes, VolatileMemory};
    /// #   let mut mem = [0u8; 1024];
    /// #   let mut mem_ref = &mut mem[..];
    /// #   let vslice = mem_ref.as_volatile_slice();
    ///     let res = vslice.write_slice(&[1,2,3,4,5], 256);
    /// #   assert!(res.is_ok());
    /// #   assert_eq!(res.unwrap(), ());
    /// ```
    fn write_slice(&self, buf: &[u8], addr: usize) -> Result<()> {
        let len = self.write(buf, addr)?;
        if len != buf.len() {
            return Err(Error::PartialBuffer {
                expected: buf.len(),
                completed: len,
            });
        }
        Ok(())
    }

    /// # Examples
    /// * Read a slice of size 16 at offset 256.
    ///
    /// ```
    /// #   use vm_memory::{Bytes, VolatileMemory};
    /// #   let mut mem = [0u8; 1024];
    /// #   let mut mem_ref = &mut mem[..];
    /// #   let vslice = mem_ref.as_volatile_slice();
    ///     let buf = &mut [0u8; 16];
    ///     let res = vslice.read_slice(buf, 256);
    /// #   assert!(res.is_ok());
    /// #   assert_eq!(res.unwrap(), ());
    /// ```
    fn read_slice(&self, buf: &mut [u8], addr: usize) -> Result<()> {
        let len = self.read(buf, addr)?;
        if len != buf.len() {
            return Err(Error::PartialBuffer {
                expected: buf.len(),
                completed: len,
            });
        }
        Ok(())
    }

    /// # Examples
    ///
    /// * Read bytes from /dev/urandom
    ///
    /// ```
    /// # use vm_memory::{Bytes, VolatileMemory};
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_read_random() -> Result<u32, ()> {
    /// #     let mut mem = [0u8; 1024];
    /// #     let mut mem_ref = &mut mem[..];
    /// #     let vslice = mem_ref.as_volatile_slice();
    ///       let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///       vslice.read_from(32, &mut file, 128).map_err(|_| ())?;
    ///       let rand_val: u32 = vslice.read_obj(40).map_err(|_| ())?;
    /// #     Ok(rand_val)
    /// # }
    /// ```
    fn read_from<F>(&self, addr: usize, src: &mut F, count: usize) -> Result<usize>
    where
        F: Read,
    {
        let end = self.compute_end_offset(addr, count)?;
        unsafe {
            // It is safe to overwrite the volatile memory. Accessing the guest
            // memory as a mutable slice is OK because nothing assumes another
            // thread won't change what is loaded.
            let dst = &mut self.as_mut_slice()[addr..end];
            loop {
                match src.read(dst) {
                    Ok(n) => break Ok(n),
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => break Err(Error::IOError(e)),
                }
            }
        }
    }

    /// # Examples
    ///
    /// * Read bytes from /dev/urandom
    ///
    /// ```
    /// # use vm_memory::{Bytes, VolatileMemory};
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_read_random() -> Result<u32, ()> {
    /// #     let mut mem = [0u8; 1024];
    /// #     let mut mem_ref = &mut mem[..];
    /// #     let vslice = mem_ref.as_volatile_slice();
    ///       let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///       vslice.read_exact_from(32, &mut file, 128).map_err(|_| ())?;
    ///       let rand_val: u32 = vslice.read_obj(40).map_err(|_| ())?;
    /// #     Ok(rand_val)
    /// # }
    /// ```
    fn read_exact_from<F>(&self, addr: usize, src: &mut F, count: usize) -> Result<()>
    where
        F: Read,
    {
        let end = self.compute_end_offset(addr, count)?;
        unsafe {
            // It is safe to overwrite the volatile memory. Accessing the guest
            // memory as a mutable slice is OK because nothing assumes another
            // thread won't change what is loaded.
            let dst = &mut self.as_mut_slice()[addr..end];
            src.read_exact(dst).map_err(Error::IOError)?;
        }
        Ok(())
    }

    /// # Examples
    ///
    /// * Write 128 bytes to /dev/null
    ///
    /// ```
    /// # use vm_memory::{Bytes, VolatileMemory};
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_write_null() -> Result<(), ()> {
    /// #     let mut mem = [0u8; 1024];
    /// #     let mut mem_ref = &mut mem[..];
    /// #     let vslice = mem_ref.as_volatile_slice();
    ///       let mut file = File::open(Path::new("/dev/null")).map_err(|_| ())?;
    ///       vslice.write_to(32, &mut file, 128).map_err(|_| ())?;
    /// #     Ok(())
    /// # }
    /// ```
    fn write_to<F>(&self, addr: usize, dst: &mut F, count: usize) -> Result<usize>
    where
        F: Write,
    {
        let end = self.compute_end_offset(addr, count)?;
        unsafe {
            // It is safe to read from volatile memory. Accessing the guest
            // memory as a slice is OK because nothing assumes another thread
            // won't change what is loaded.
            let src = &self.as_mut_slice()[addr..end];
            loop {
                match dst.write(src) {
                    Ok(n) => break Ok(n),
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => break Err(Error::IOError(e)),
                }
            }
        }
    }

    /// # Examples
    ///
    /// * Write 128 bytes to /dev/null
    ///
    /// ```
    /// # use vm_memory::{Bytes, VolatileMemory};
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_write_null() -> Result<(), ()> {
    /// #     let mut mem = [0u8; 1024];
    /// #     let mut mem_ref = &mut mem[..];
    /// #     let vslice = mem_ref.as_volatile_slice();
    ///       let mut file = File::open(Path::new("/dev/null")).map_err(|_| ())?;
    ///       vslice.write_all_to(32, &mut file, 128).map_err(|_| ())?;
    /// #     Ok(())
    /// # }
    /// ```
    fn write_all_to<F>(&self, addr: usize, dst: &mut F, count: usize) -> Result<()>
    where
        F: Write,
    {
        let end = self.compute_end_offset(addr, count)?;
        unsafe {
            // It is safe to read from volatile memory. Accessing the guest
            // memory as a slice is OK because nothing assumes another thread
            // won't change what is loaded.
            let src = &self.as_mut_slice()[addr..end];
            dst.write_all(src).map_err(Error::IOError)?;
        }
        Ok(())
    }
}

impl VolatileMemory for VolatileSlice<'_> {
    fn len(&self) -> usize {
        self.size
    }

    fn get_slice(&self, offset: usize, count: usize) -> Result<VolatileSlice> {
        let _ = self.compute_end_offset(offset, count)?;
        Ok(unsafe {
            // This is safe because the pointer is range-checked by compute_end_offset, and
            // the lifetime is the same as self.
            VolatileSlice::new((self.addr as usize + offset) as *mut u8, count)
        })
    }
}

/// A memory location that supports volatile access to an instance of `T`.
///
/// # Examples
///
/// ```
/// # use vm_memory::VolatileRef;
///   let mut v = 5u32;
///   assert_eq!(v, 5);
///   let v_ref = unsafe { VolatileRef::<u32>::new(&mut v as *mut u32 as *mut u8) };
///   assert_eq!(v_ref.load(), 5);
///   v_ref.store(500);
///   assert_eq!(v, 500);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct VolatileRef<'a, T: ByteValued>
where
    T: 'a,
{
    addr: *mut Packed<T>,
    phantom: PhantomData<&'a T>,
}

#[allow(clippy::len_without_is_empty)]
impl<'a, T: ByteValued> VolatileRef<'a, T> {
    /// Creates a [`VolatileRef`](struct.VolatileRef.html) to an instance of `T`.
    ///
    /// # Safety
    ///
    /// To use this safely, the caller must guarantee that the memory at `addr` is big enough for a
    /// `T` and is available for the duration of the lifetime of the new `VolatileRef`. The caller
    /// must also guarantee that all other users of the given chunk of memory are using volatile
    /// accesses.
    pub unsafe fn new(addr: *mut u8) -> VolatileRef<'a, T> {
        VolatileRef {
            addr: addr as *mut Packed<T>,
            phantom: PhantomData,
        }
    }

    /// Returns a pointer to the underlying memory.
    pub fn as_ptr(self) -> *mut u8 {
        self.addr as *mut u8
    }

    /// Gets the size of the referenced type `T`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::mem::size_of;
    /// # use vm_memory::VolatileRef;
    ///   let v_ref = unsafe { VolatileRef::<u32>::new(0 as *mut _) };
    ///   assert_eq!(v_ref.len(), size_of::<u32>() as usize);
    /// ```
    pub fn len(self) -> usize {
        size_of::<T>()
    }

    /// Does a volatile write of the value `v` to the address of this ref.
    #[inline(always)]
    pub fn store(self, v: T) {
        unsafe { write_volatile(self.addr, Packed::<T>(v)) };
    }

    /// Does a volatile read of the value at the address of this ref.
    #[inline(always)]
    pub fn load(self) -> T {
        // For the purposes of demonstrating why read_volatile is necessary, try replacing the code
        // in this function with the commented code below and running `cargo test --release`.
        // unsafe { *(self.addr as *const T) }
        unsafe { read_volatile(self.addr).0 }
    }

    /// Converts this to a [`VolatileSlice`](struct.VolatileSlice.html) with the same size and
    /// address.
    pub fn to_slice(self) -> VolatileSlice<'a> {
        unsafe { VolatileSlice::new(self.addr as *mut u8, size_of::<T>()) }
    }
}

/// A memory location that supports volatile access to an array of elements of type `T`.
///
/// # Examples
///
/// ```
/// # use vm_memory::VolatileRef;
///   let mut v = 5u32;
///   assert_eq!(v, 5);
///   let v_ref = unsafe { VolatileRef::<u32>::new(&mut v as *mut u32 as *mut u8) };
///   assert_eq!(v_ref.load(), 5);
///   v_ref.store(500);
///   assert_eq!(v, 500);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct VolatileArrayRef<'a, T: ByteValued>
where
    T: 'a,
{
    addr: *mut u8,
    nelem: usize,
    phantom: PhantomData<&'a T>,
}

impl<'a, T: ByteValued> VolatileArrayRef<'a, T> {
    /// Creates a [`VolatileArrayRef`](struct.VolatileArrayRef.html) to an array of elements of
    /// type `T`.
    ///
    /// # Safety
    ///
    /// To use this safely, the caller must guarantee that the memory at `addr` is big enough for
    /// `nelem` values of type `T` and is available for the duration of the lifetime of the new
    /// `VolatileRef`. The caller must also guarantee that all other users of the given chunk of
    /// memory are using volatile accesses.
    pub unsafe fn new(addr: *mut u8, nelem: usize) -> VolatileArrayRef<'a, T> {
        VolatileArrayRef {
            addr,
            nelem,
            phantom: PhantomData,
        }
    }

    /// Returns `true` if this array is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use vm_memory::{VolatileRef, VolatileArrayRef};
    ///   let v_array = unsafe { VolatileArrayRef::<u32>::new(0 as *mut _, 0) };
    ///   assert!(v_array.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.nelem == 0
    }

    /// Returns the number of elements in the array.
    ///
    /// # Examples
    ///
    /// ```
    /// # use vm_memory::{VolatileRef, VolatileArrayRef};
    ///   let v_array = unsafe { VolatileArrayRef::<u32>::new(0 as *mut _, 1) };
    ///   assert_eq!(v_array.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.nelem
    }

    /// Returns the size of `T`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::mem::size_of;
    /// # use vm_memory::VolatileRef;
    ///   let v_ref = unsafe { VolatileRef::<u32>::new(0 as *mut _) };
    ///   assert_eq!(v_ref.len(), size_of::<u32>() as usize);
    /// ```
    pub fn element_size(&self) -> usize {
        size_of::<T>()
    }

    /// Returns a pointer to the underlying memory.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Converts this to a `VolatileSlice` with the same size and address.
    pub fn to_slice(&self) -> VolatileSlice<'a> {
        unsafe { VolatileSlice::new(self.addr, self.nelem * self.element_size()) }
    }

    /// Does a volatile read of the element at `index`.
    pub fn ref_at(&self, index: usize) -> VolatileRef<'a, T> {
        assert!(index < self.nelem);
        // Safe because the memory has the same lifetime and points to a subset of the
        // memory of the VolatileArrayRef.
        unsafe {
            // byteofs must fit in an isize as it was checked in get_array_ref.
            let byteofs = (self.element_size() * index) as isize;
            let ptr = self.as_ptr().offset(byteofs);
            VolatileRef::new(ptr)
        }
    }

    /// Does a volatile read of the element at `index`.
    pub fn load(&self, index: usize) -> T {
        self.ref_at(index).load()
    }

    /// Does a volatile write of the element at `index`.
    pub fn store(&self, index: usize, value: T) {
        self.ref_at(index).store(value)
    }

    /// Copies as many elements of type `T` as possible from this array to `buf`.
    ///
    /// Copies `self.len()` or `buf.len()` times the size of `T` bytes, whichever is smaller,
    /// to `buf`. The copy happens from smallest to largest address in `T` sized chunks
    /// using volatile reads.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # use vm_memory::VolatileMemory;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let mem_ref = &mut mem[..];
    /// let vslice = mem_ref.get_slice(0, 32).map_err(|_| ())?;
    /// let mut buf = [5u8; 16];
    /// vslice.copy_to(&mut buf[..]);
    /// for v in &buf[..] {
    ///     assert_eq!(buf[0], 0);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_to(&self, buf: &mut [T]) -> usize {
        let mut addr = self.addr;
        let mut i = 0;
        for v in buf.iter_mut().take(self.len()) {
            unsafe {
                // read_volatile is safe because the pointers are range-checked when
                // the slices are created, and they never escape the VolatileSlices.
                // ptr::add is safe because get_array_ref() validated that
                // size_of::<T>() * self.len() fits in an isize.
                *v = read_volatile(addr as *const Packed<T>).0;
                addr = addr.add(self.element_size());
            };
            i += 1;
        }
        i
    }

    /// Copies as many bytes as possible from this slice to the provided `slice`.
    ///
    /// The copies happen in an undefined order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use vm_memory::VolatileMemory;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let mem_ref = &mut mem[..];
    /// let vslice = mem_ref.get_slice(0, 32).map_err(|_| ())?;
    /// vslice.copy_to_volatile_slice(vslice.get_slice(16, 16).map_err(|_| ())?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_to_volatile_slice(&self, slice: VolatileSlice) {
        unsafe {
            // Safe because the pointers are range-checked when the slices
            // are created, and they never escape the VolatileSlices.
            // FIXME: ... however, is it really okay to mix non-volatile
            // operations such as copy with read_volatile and write_volatile?
            copy(
                self.addr,
                slice.addr,
                min(self.len() * self.element_size(), slice.size),
            );
        }
    }

    /// Copies as many elements of type `T` as possible from `buf` to this slice.
    ///
    /// Copies `self.len()` or `buf.len()` times the size of `T` bytes, whichever is smaller,
    /// to this slice's memory. The copy happens from smallest to largest address in
    /// `T` sized chunks using volatile writes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # use vm_memory::VolatileMemory;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let mem_ref = &mut mem[..];
    /// let vslice = mem_ref.get_slice(0, 32).map_err(|_| ())?;
    /// let buf = [5u8; 64];
    /// vslice.copy_from(&buf[..]);
    /// for i in 0..4 {
    ///     assert_eq!(vslice.get_ref::<u32>(i * 4).map_err(|_| ())?.load(), 0x05050505);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_from(&self, buf: &[T]) {
        let mut addr = self.addr;
        for &v in buf.iter().take(self.len()) {
            unsafe {
                // write_volatile is safe because the pointers are range-checked when
                // the slices are created, and they never escape the VolatileSlices.
                // ptr::add is safe because get_array_ref() validated that
                // size_of::<T>() * self.len() fits in an isize.
                write_volatile(addr as *mut Packed<T>, Packed::<T>(v));
                addr = addr.add(self.element_size());
            }
        }
    }
}

impl<'a> From<VolatileSlice<'a>> for VolatileArrayRef<'a, u8> {
    fn from(slice: VolatileSlice<'a>) -> Self {
        // Safe because the result has the same lifetime and points to the same
        // memory as the incoming VolatileSlice.
        unsafe { VolatileArrayRef::new(slice.as_ptr(), slice.len()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread::{sleep, spawn};
    use std::time::Duration;

    use matches::assert_matches;
    use vmm_sys_util::tempfile::TempFile;

    #[derive(Clone)]
    struct VecMem {
        mem: Arc<Vec<u8>>,
    }

    impl VecMem {
        fn new(size: usize) -> VecMem {
            let mut mem = Vec::new();
            mem.resize(size, 0);
            VecMem { mem: Arc::new(mem) }
        }
    }

    impl VolatileMemory for VecMem {
        fn len(&self) -> usize {
            self.mem.len()
        }

        fn get_slice(&self, offset: usize, count: usize) -> Result<VolatileSlice> {
            let _ = self.compute_end_offset(offset, count)?;
            Ok(unsafe {
                VolatileSlice::new((self.mem.as_ptr() as usize + offset) as *mut _, count)
            })
        }
    }

    #[test]
    fn test_display_error() {
        assert_eq!(
            format!("{}", Error::OutOfBounds { addr: 0x10 }),
            "address 0x10 is out of bounds"
        );

        assert_eq!(
            format!(
                "{}",
                Error::Overflow {
                    base: 0x0,
                    offset: 0x10
                }
            ),
            "address 0x0 offset by 0x10 would overflow"
        );

        assert_eq!(
            format!(
                "{}",
                Error::TooBig {
                    nelements: 100_000,
                    size: 1_000_000_000
                }
            ),
            "100000 elements of size 1000000000 would overflow a usize"
        );

        assert_eq!(
            format!(
                "{}",
                Error::Misaligned {
                    addr: 0x4,
                    alignment: 8
                }
            ),
            "address 0x4 is not aligned to 8"
        );

        assert_eq!(
            format!(
                "{}",
                Error::PartialBuffer {
                    expected: 100,
                    completed: 90
                }
            ),
            "only used 90 bytes in 100 long buffer"
        );
    }

    #[test]
    fn misaligned_ref() {
        let mut a = [0u8; 3];
        let a_ref = &mut a[..];
        unsafe {
            assert!(
                a_ref.aligned_as_ref::<u16>(0).is_err() ^ a_ref.aligned_as_ref::<u16>(1).is_err()
            );
            assert!(
                a_ref.aligned_as_mut::<u16>(0).is_err() ^ a_ref.aligned_as_mut::<u16>(1).is_err()
            );
        }
    }

    #[test]
    fn atomic_store() {
        let mut a = [0usize; 1];
        {
            let a_ref = unsafe {
                VolatileSlice::new(&mut a[0] as *mut usize as *mut u8, size_of::<usize>())
            };
            let atomic = a_ref.get_atomic_ref::<AtomicUsize>(0).unwrap();
            atomic.store(2usize, Ordering::Relaxed)
        }
        assert_eq!(a[0], 2);
    }

    #[test]
    fn atomic_load() {
        let mut a = [5usize; 1];
        {
            let a_ref = unsafe {
                VolatileSlice::new(&mut a[0] as *mut usize as *mut u8,
                                   size_of::<usize>())
            };
            let atomic = {
                let atomic = a_ref.get_atomic_ref::<AtomicUsize>(0).unwrap();
                assert_eq!(atomic.load(Ordering::Relaxed), 5usize);
                atomic
            };
            // To make sure we can take the atomic out of the scope we made it in:
            atomic.load(Ordering::Relaxed);
            // but not too far:
            // atomicu8
        } //.load(std::sync::atomic::Ordering::Relaxed)
        ;
    }

    #[test]
    fn misaligned_atomic() {
        let mut a = [5usize, 5usize];
        let a_ref =
            unsafe { VolatileSlice::new(&mut a[0] as *mut usize as *mut u8, size_of::<usize>()) };
        assert!(a_ref.get_atomic_ref::<AtomicUsize>(0).is_ok());
        assert!(a_ref.get_atomic_ref::<AtomicUsize>(1).is_err());
    }

    #[test]
    fn ref_store() {
        let mut a = [0u8; 1];
        {
            let a_ref = &mut a[..];
            let v_ref = a_ref.get_ref(0).unwrap();
            v_ref.store(2u8);
        }
        assert_eq!(a[0], 2);
    }

    #[test]
    fn ref_load() {
        let mut a = [5u8; 1];
        {
            let a_ref = &mut a[..];
            let c = {
                let v_ref = a_ref.get_ref::<u8>(0).unwrap();
                assert_eq!(v_ref.load(), 5u8);
                v_ref
            };
            // To make sure we can take a v_ref out of the scope we made it in:
            c.load();
            // but not too far:
            // c
        } //.load()
        ;
    }

    #[test]
    fn ref_to_slice() {
        let mut a = [1u8; 5];
        let a_ref = &mut a[..];
        let v_ref = a_ref.get_ref(1).unwrap();
        v_ref.store(0x1234_5678u32);
        let ref_slice = v_ref.to_slice();
        assert_eq!(v_ref.as_ptr() as usize, ref_slice.as_ptr() as usize);
        assert_eq!(v_ref.len(), ref_slice.len());
        assert!(!ref_slice.is_empty());
    }

    #[test]
    fn observe_mutate() {
        let a = VecMem::new(1);
        let a_clone = a.clone();
        let v_ref = a.get_ref::<u8>(0).unwrap();
        v_ref.store(99);
        spawn(move || {
            sleep(Duration::from_millis(10));
            let clone_v_ref = a_clone.get_ref::<u8>(0).unwrap();
            clone_v_ref.store(0);
        });

        // Technically this is a race condition but we have to observe the v_ref's value changing
        // somehow and this helps to ensure the sleep actually happens before the store rather then
        // being reordered by the compiler.
        assert_eq!(v_ref.load(), 99);

        // Granted we could have a machine that manages to perform this many volatile loads in the
        // amount of time the spawned thread sleeps, but the most likely reason the retry limit will
        // get reached is because v_ref.load() is not actually performing the required volatile read
        // or v_ref.store() is not doing a volatile write. A timer based solution was avoided
        // because that might use a syscall which could hint the optimizer to reload v_ref's pointer
        // regardless of volatile status. Note that we use a longer retry duration for optimized
        // builds.
        #[cfg(debug_assertions)]
        const RETRY_MAX: usize = 500_000_000;
        #[cfg(not(debug_assertions))]
        const RETRY_MAX: usize = 10_000_000_000;

        let mut retry = 0;
        while v_ref.load() == 99 && retry < RETRY_MAX {
            retry += 1;
        }

        assert_ne!(retry, RETRY_MAX, "maximum retry exceeded");
        assert_eq!(v_ref.load(), 0);
    }

    #[test]
    fn mem_is_empty() {
        let a = VecMem::new(100);
        assert!(!a.is_empty());

        let a = VecMem::new(0);
        assert!(a.is_empty());
    }

    #[test]
    fn slice_len() {
        let mem = VecMem::new(100);
        let slice = mem.get_slice(0, 27).unwrap();
        assert_eq!(slice.len(), 27);
        assert!(!slice.is_empty());

        let slice = mem.get_slice(34, 27).unwrap();
        assert_eq!(slice.len(), 27);
        assert!(!slice.is_empty());

        let slice = slice.get_slice(20, 5).unwrap();
        assert_eq!(slice.len(), 5);
        assert!(!slice.is_empty());

        let slice = mem.get_slice(34, 0).unwrap();
        assert!(slice.is_empty());
    }

    #[test]
    fn slice_offset() {
        let mem = VecMem::new(100);
        let slice = mem.get_slice(0, 100).unwrap();
        assert!(slice.write(&[1; 80], 10).is_ok());

        assert!(slice.offset(101).is_err());

        let maybe_offset_slice = slice.offset(10);
        assert!(maybe_offset_slice.is_ok());
        let offset_slice = maybe_offset_slice.unwrap();
        assert_eq!(offset_slice.len(), 90);
        let mut buf = [0; 90];
        assert!(offset_slice.read(&mut buf, 0).is_ok());
        assert_eq!(&buf[0..80], &[1; 80][0..80]);
        assert_eq!(&buf[80..90], &[0; 10][0..10]);
    }

    #[test]
    fn slice_copy_to() {
        let mut a = [2, 4, 6, 8, 10];
        let mut b = [0u8; 4];
        let mut c = [0u8; 6];
        let a_ref = &mut a[..];
        let v_ref = a_ref.get_slice(0, a_ref.len()).unwrap();
        v_ref.copy_to(&mut b[..]);
        v_ref.copy_to(&mut c[..]);
        assert_eq!(b[0..4], a_ref[0..4]);
        assert_eq!(c[0..5], a_ref[0..5]);
    }

    #[test]
    fn slice_copy_from() {
        let a = [2, 4, 6, 8, 10];
        let mut b = [0u8; 4];
        let mut c = [0u8; 6];
        let b_ref = &mut b[..];
        let v_ref = b_ref.get_slice(0, b_ref.len()).unwrap();
        v_ref.copy_from(&a[..]);
        assert_eq!(b_ref[0..4], a[0..4]);

        let c_ref = &mut c[..];
        let v_ref = c_ref.get_slice(0, c_ref.len()).unwrap();
        v_ref.copy_from(&a[..]);
        assert_eq!(c_ref[0..5], a[0..5]);
    }

    #[test]
    fn slice_copy_to_volatile_slice() {
        let mut a = [2, 4, 6, 8, 10];
        let a_ref = &mut a[..];
        let a_slice = a_ref.get_slice(0, a_ref.len()).unwrap();

        let mut b = [0u8; 4];
        let b_ref = &mut b[..];
        let b_slice = b_ref.get_slice(0, b_ref.len()).unwrap();

        a_slice.copy_to_volatile_slice(b_slice);
        assert_eq!(b, [2, 4, 6, 8]);
    }

    #[test]
    fn slice_overflow_error() {
        use std::usize::MAX;
        let a = VecMem::new(1);
        let res = a.get_slice(MAX, 1).unwrap_err();
        assert_matches!(
            res,
            Error::Overflow {
                base: MAX,
                offset: 1,
            }
        );
    }

    #[test]
    fn slice_oob_error() {
        let a = VecMem::new(100);
        a.get_slice(50, 50).unwrap();
        let res = a.get_slice(55, 50).unwrap_err();
        assert_matches!(res, Error::OutOfBounds { addr: 105 });
    }

    #[test]
    fn ref_overflow_error() {
        use std::usize::MAX;
        let a = VecMem::new(1);
        let res = a.get_ref::<u8>(MAX).unwrap_err();
        assert_matches!(
            res,
            Error::Overflow {
                base: MAX,
                offset: 1,
            }
        );
    }

    #[test]
    fn ref_oob_error() {
        let a = VecMem::new(100);
        a.get_ref::<u8>(99).unwrap();
        let res = a.get_ref::<u16>(99).unwrap_err();
        assert_matches!(res, Error::OutOfBounds { addr: 101 });
    }

    #[test]
    fn ref_oob_too_large() {
        let a = VecMem::new(3);
        let res = a.get_ref::<u32>(0).unwrap_err();
        assert_matches!(res, Error::OutOfBounds { addr: 4 });
    }

    #[test]
    fn slice_store() {
        let a = VecMem::new(5);
        let s = a.as_volatile_slice();
        let r = a.get_ref(2).unwrap();
        r.store(9u16);
        assert_eq!(s.read_obj::<u16>(2).unwrap(), 9);
    }

    #[test]
    fn test_write_past_end() {
        let a = VecMem::new(5);
        let s = a.as_volatile_slice();
        let res = s.write(&[1, 2, 3, 4, 5, 6], 0);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 5);
    }

    #[test]
    fn slice_read_and_write() {
        let a = VecMem::new(5);
        let s = a.as_volatile_slice();
        let sample_buf = [1, 2, 3];
        assert!(s.write(&sample_buf, 5).is_err());
        assert!(s.write(&sample_buf, 2).is_ok());
        let mut buf = [0u8; 3];
        assert!(s.read(&mut buf, 5).is_err());
        assert!(s.read_slice(&mut buf, 2).is_ok());
        assert_eq!(buf, sample_buf);
    }

    #[test]
    fn obj_read_and_write() {
        let a = VecMem::new(5);
        let s = a.as_volatile_slice();
        assert!(s.write_obj(55u16, 4).is_err());
        assert!(s.write_obj(55u16, core::usize::MAX).is_err());
        assert!(s.write_obj(55u16, 2).is_ok());
        assert_eq!(s.read_obj::<u16>(2).unwrap(), 55u16);
        assert!(s.read_obj::<u16>(4).is_err());
        assert!(s.read_obj::<u16>(core::usize::MAX).is_err());
    }

    #[test]
    fn mem_read_and_write() {
        let a = VecMem::new(5);
        let s = a.as_volatile_slice();
        assert!(s.write_obj(!0u32, 1).is_ok());
        let mut file = if cfg!(unix) {
            File::open(Path::new("/dev/zero")).unwrap()
        } else {
            File::open(Path::new("c:\\Windows\\system32\\ntoskrnl.exe")).unwrap()
        };
        assert!(s.read_exact_from(2, &mut file, size_of::<u32>()).is_err());
        assert!(s
            .read_exact_from(core::usize::MAX, &mut file, size_of::<u32>())
            .is_err());

        assert!(s.read_exact_from(1, &mut file, size_of::<u32>()).is_ok());

        let mut f = TempFile::new().unwrap().into_file();
        assert!(s.read_exact_from(1, &mut f, size_of::<u32>()).is_err());
        format!("{:?}", s.read_exact_from(1, &mut f, size_of::<u32>()));

        let value = s.read_obj::<u32>(1).unwrap();
        if cfg!(unix) {
            assert_eq!(value, 0);
        } else {
            assert_eq!(value, 0x0090_5a4d);
        }

        let mut sink = Vec::new();
        assert!(s.write_all_to(1, &mut sink, size_of::<u32>()).is_ok());
        assert!(s.write_all_to(2, &mut sink, size_of::<u32>()).is_err());
        assert!(s
            .write_all_to(core::usize::MAX, &mut sink, size_of::<u32>())
            .is_err());
        format!("{:?}", s.write_all_to(2, &mut sink, size_of::<u32>()));
        if cfg!(unix) {
            assert_eq!(sink, vec![0; size_of::<u32>()]);
        } else {
            assert_eq!(sink, vec![0x4d, 0x5a, 0x90, 0x00]);
        };
    }

    #[test]
    fn unaligned_read_and_write() {
        let a = VecMem::new(7);
        let s = a.as_volatile_slice();
        let sample_buf: [u8; 7] = [1, 2, 0xAA, 0xAA, 0xAA, 0xAA, 4];
        assert!(s.write_slice(&sample_buf, 0).is_ok());
        let r = a.get_ref::<u32>(2).unwrap();
        assert_eq!(r.load(), 0xAAAA_AAAA);

        r.store(0x5555_5555);
        let sample_buf: [u8; 7] = [1, 2, 0x55, 0x55, 0x55, 0x55, 4];
        let mut buf: [u8; 7] = Default::default();
        assert!(s.read_slice(&mut buf, 0).is_ok());
        assert_eq!(buf, sample_buf);
    }

    #[test]
    fn ref_array_from_slice() {
        let mut a = [2, 4, 6, 8, 10];
        let a_vec = a.to_vec();
        let a_ref = &mut a[..];
        let a_slice = a_ref.get_slice(0, a_ref.len()).unwrap();
        let a_array_ref: VolatileArrayRef<u8> = a_slice.into();
        for (i, entry) in a_vec.iter().enumerate() {
            assert_eq!(&a_array_ref.load(i), entry);
        }
    }

    #[test]
    fn ref_array_store() {
        let mut a = [0u8; 5];
        {
            let a_ref = &mut a[..];
            let v_ref = a_ref.get_array_ref(1, 4).unwrap();
            v_ref.store(1, 2u8);
            v_ref.store(2, 4u8);
            v_ref.store(3, 6u8);
        }
        let expected = [2u8, 4u8, 6u8];
        assert_eq!(a[2..=4], expected);
    }

    #[test]
    fn ref_array_load() {
        let mut a = [0, 0, 2, 3, 10];
        {
            let a_ref = &mut a[..];
            let c = {
                let v_ref = a_ref.get_array_ref::<u8>(1, 4).unwrap();
                assert_eq!(v_ref.load(1), 2u8);
                assert_eq!(v_ref.load(2), 3u8);
                assert_eq!(v_ref.load(3), 10u8);
                v_ref
            };
            // To make sure we can take a v_ref out of the scope we made it in:
            c.load(0);
            // but not too far:
            // c
        } //.load()
        ;
    }

    #[test]
    fn ref_array_overflow() {
        let mut a = [0, 0, 2, 3, 10];
        let a_ref = &mut a[..];
        let res = a_ref.get_array_ref::<u32>(4, usize::MAX).unwrap_err();
        assert_matches!(
            res,
            Error::TooBig {
                nelements: usize::MAX,
                size: 4,
            }
        );
    }
}

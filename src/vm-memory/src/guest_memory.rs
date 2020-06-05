// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Traits to track and access the physical memory of the guest.
//!
//! To make the abstraction as generic as possible, all the core traits declared here only define
//! methods to access guest's memory, and never define methods to manage (create, delete, insert,
//! remove etc) guest's memory. This way, the guest memory consumers (virtio device drivers,
//! vhost drivers and boot loaders etc) may be decoupled from the guest memory provider (typically
//! a hypervisor).
//!
//! Traits and Structs
//! - [GuestAddress](struct.GuestAddress.html): represents a guest physical address (GPA).
//! - [MemoryRegionAddress](struct.MemoryRegionAddress.html): represents an offset inside a region.
//! - [GuestMemoryRegion](trait.GuestMemoryRegion.html): represent a continuous region of guest's
//! physical memory.
//! - [GuestMemory](trait.GuestMemory.html): represent a collection of GuestMemoryRegion objects.
//! The main responsibilities of the GuestMemory trait are:
//!     - hide the detail of accessing guest's physical address.
//!     - map a request address to a GuestMemoryRegion object and relay the request to it.
//!     - handle cases where an access request spanning two or more GuestMemoryRegion objects.
//!
//! Whenever a collection of GuestMemoryRegion objects is mutable,
//! [GuestAddressSpace](trait.GuestAddressSpace.html) should be implemented
//! for clients to obtain a [GuestMemory] reference or smart pointer.

use std::convert::From;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Read, Write};
use std::ops::{BitAnd, BitOr, Deref};
use std::rc::Rc;
use std::sync::Arc;

use crate::address::{Address, AddressValue};
use crate::bytes::Bytes;
use crate::volatile_memory;

static MAX_ACCESS_CHUNK: usize = 4096;

/// Errors associated with handling guest memory accesses.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    /// Failure in finding a guest address in any memory regions mapped by this guest.
    InvalidGuestAddress(GuestAddress),
    /// Couldn't read/write from the given source.
    IOError(io::Error),
    /// Incomplete read or write.
    PartialBuffer { expected: usize, completed: usize },
    /// Requested backend address is out of range.
    InvalidBackendAddress,
    /// Host virtual address not available.
    HostAddressNotAvailable,
}

impl From<volatile_memory::Error> for Error {
    fn from(e: volatile_memory::Error) -> Self {
        match e {
            volatile_memory::Error::OutOfBounds { .. } => Error::InvalidBackendAddress,
            volatile_memory::Error::Overflow { .. } => Error::InvalidBackendAddress,
            volatile_memory::Error::TooBig { .. } => Error::InvalidBackendAddress,
            volatile_memory::Error::Misaligned { .. } => Error::InvalidBackendAddress,
            volatile_memory::Error::IOError(e) => Error::IOError(e),
            volatile_memory::Error::PartialBuffer {
                expected,
                completed,
            } => Error::PartialBuffer {
                expected,
                completed,
            },
        }
    }
}

/// Result of guest memory operations.
pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Guest memory error: ")?;
        match self {
            Error::InvalidGuestAddress(addr) => {
                write!(f, "invalid guest address {}", addr.raw_value())
            }
            Error::IOError(error) => write!(f, "{}", error),
            Error::PartialBuffer {
                expected,
                completed,
            } => write!(
                f,
                "only used {} bytes in {} long buffer",
                completed, expected,
            ),
            Error::InvalidBackendAddress => write!(f, "invalid backend address"),
            Error::HostAddressNotAvailable => write!(f, "host virtual address not available"),
        }
    }
}

/// Represents a guest physical address (GPA).
///
/// # Notes:
/// On ARM64, a 32-bit hypervisor may be used to support a 64-bit guest. For simplicity,
/// `u64` is used to store the the raw value no matter if the guest a 32-bit or 64-bit virtual
/// machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct GuestAddress(pub u64);
impl_address_ops!(GuestAddress, u64);

/// Represents an offset inside a region.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MemoryRegionAddress(pub u64);
impl_address_ops!(MemoryRegionAddress, u64);

/// Type of the raw value stored in a GuestAddress object.
pub type GuestUsize = <GuestAddress as AddressValue>::V;

/// Represents the start point within a `File` that backs a `GuestMemoryRegion`.
#[derive(Clone, Debug)]
pub struct FileOffset {
    file: Arc<File>,
    start: u64,
}

impl FileOffset {
    /// Creates a new `FileOffset` object.
    pub fn new(file: File, start: u64) -> Self {
        FileOffset::from_arc(Arc::new(file), start)
    }

    /// Creates a new `FileOffset` object based on an exiting `Arc<File>`.
    pub fn from_arc(file: Arc<File>, start: u64) -> Self {
        FileOffset { file, start }
    }

    /// Returns a reference to the inner `File` object.
    pub fn file(&self) -> &File {
        &self.file.as_ref()
    }

    /// Return a reference to the inner `Arc<File>` object.
    pub fn arc(&self) -> &Arc<File> {
        &self.file
    }

    /// Returns the start offset within the file.
    pub fn start(&self) -> u64 {
        self.start
    }
}

/// Represents a continuous region of guest physical memory.
#[allow(clippy::len_without_is_empty)]
pub trait GuestMemoryRegion: Bytes<MemoryRegionAddress, E = Error> {
    /// Returns the size of the region.
    fn len(&self) -> GuestUsize;

    /// Returns the minimum (inclusive) address managed by the region.
    fn start_addr(&self) -> GuestAddress;

    /// Returns the maximum (inclusive) address managed by the region.
    fn last_addr(&self) -> GuestAddress {
        // unchecked_add is safe as the region bounds were checked when it was created.
        self.start_addr().unchecked_add(self.len() - 1)
    }

    /// Returns the given address if it is within this region.
    fn check_address(&self, addr: MemoryRegionAddress) -> Option<MemoryRegionAddress> {
        if self.address_in_range(addr) {
            Some(addr)
        } else {
            None
        }
    }

    /// Returns `true` if the given address is within this region.
    fn address_in_range(&self, addr: MemoryRegionAddress) -> bool {
        addr.raw_value() < self.len()
    }

    /// Returns the address plus the offset if it is in this region.
    fn checked_offset(
        &self,
        base: MemoryRegionAddress,
        offset: usize,
    ) -> Option<MemoryRegionAddress> {
        base.checked_add(offset as u64)
            .and_then(|addr| self.check_address(addr))
    }

    /// Tries to convert an absolute address to a relative address within this region.
    ///
    /// Returns `None` if `addr` is out of the bounds of this region.
    fn to_region_addr(&self, addr: GuestAddress) -> Option<MemoryRegionAddress> {
        addr.checked_offset_from(self.start_addr())
            .and_then(|offset| self.check_address(MemoryRegionAddress(offset)))
    }

    /// Returns the host virtual address corresponding to the region address.
    ///
    /// Some [`GuestMemory`](trait.GuestMemory.html) implementations, like `GuestMemoryMmap`,
    /// have the capability to mmap guest address range into host virtual address space for
    /// direct access, so the corresponding host virtual address may be passed to other subsystems.
    ///
    /// # Note
    /// The underlying guest memory is not protected from memory aliasing, which breaks the
    /// Rust memory safety model. It's the caller's responsibility to ensure that there's no
    /// concurrent accesses to the underlying guest memory.
    fn get_host_address(&self, _addr: MemoryRegionAddress) -> Result<*mut u8> {
        Err(Error::HostAddressNotAvailable)
    }

    /// Returns information regarding the file and offset backing this memory region.
    fn file_offset(&self) -> Option<&FileOffset> {
        None
    }

    /// Returns a slice corresponding to the data in the region.
    ///
    /// Returns `None` if the region does not support slice-based access.
    ///
    /// # Safety
    ///
    /// Unsafe because of possible aliasing.
    unsafe fn as_slice(&self) -> Option<&[u8]> {
        None
    }

    /// Returns a mutable slice corresponding to the data in the region.
    ///
    /// Returns `None` if the region does not support slice-based access.
    ///
    /// # Safety
    ///
    /// Unsafe because of possible aliasing.
    unsafe fn as_mut_slice(&self) -> Option<&mut [u8]> {
        None
    }

    /// Returns a [`VolatileSlice`](struct.VolatileSlice.html) of `count` bytes starting at
    /// `offset`.
    #[allow(unused_variables)]
    fn get_slice(
        &self,
        offset: MemoryRegionAddress,
        count: usize,
    ) -> Result<volatile_memory::VolatileSlice> {
        Err(Error::HostAddressNotAvailable)
    }

    /// Gets a slice of memory for the entire region that supports volatile access.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::{GuestAddress, MmapRegion, GuestRegionMmap, GuestMemoryRegion};
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::volatile_memory::{VolatileMemory, VolatileSlice, VolatileRef};
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// # fn test_as_volatile_slice() {
    ///     let region =
    ///         GuestRegionMmap::new(MmapRegion::new(0x400).unwrap(), GuestAddress(0x0))
    ///         .unwrap();
    ///     let slice = region.as_volatile_slice().unwrap();
    ///     let v = 42u32;
    ///     let r = slice.get_ref::<u32>(0x200).unwrap();
    ///     r.store(v);
    ///     assert_eq!(r.load(), v);
    /// # }
    /// # #[cfg(feature = "backend-mmap")]
    /// # test_as_volatile_slice();
    /// ```
    fn as_volatile_slice(&self) -> Result<volatile_memory::VolatileSlice> {
        self.get_slice(MemoryRegionAddress(0), self.len() as usize)
    }
}

/// GuestAddressSpace provides a way to retrieve a GuestMemory object.
/// The vm-memory crate already provides trivial implementation for
/// references to GuestMemory or reference-counted GuestMemory objects,
/// but the trait can also be implemented by any other struct in order
/// to provide temporary access to a snapshot of the memory map.
///
/// In order to support generic mutable memory maps, devices (or other things
/// that access memory) should store the memory as a GuestAddressSpace<M>.
/// This example shows that references can also be used as the GuestAddressSpace
/// implementation, providing a zero-cost abstraction whenever immutable memory
/// maps are sufficient.
///
/// ```
/// # use std::sync::Arc;
/// # #[cfg(feature = "backend-mmap")]
/// # use vm_memory::GuestMemoryMmap;
/// # #[cfg(feature = "backend-atomic")]
/// # use vm_memory::GuestMemoryAtomic;
/// # use vm_memory::{GuestAddress, GuestMemory, GuestAddressSpace};
///
/// pub struct VirtioDevice<AS: GuestAddressSpace> {
///     mem: Option<AS>,
/// }
///
/// impl<AS: GuestAddressSpace> VirtioDevice<AS> {
///     fn new() -> Self {
///         VirtioDevice { mem: None }
///     }
///     fn activate(&mut self, mem: AS) {
///         self.mem = Some(mem)
///     }
/// }
///
/// # #[cfg(feature = "backend-mmap")]
/// # fn get_mmap() -> GuestMemoryMmap {
/// #     GuestMemoryMmap::from_ranges(&[(GuestAddress(0),0)]).unwrap()
/// # }
///
/// # #[cfg(feature = "backend-mmap")]
/// # fn test_1() {
/// // Using `VirtioDevice` with an immutable GuestMemoryMmap:
/// let mut for_immutable_mmap: VirtioDevice<&GuestMemoryMmap> =
///     VirtioDevice::new();
/// let mmap = get_mmap();
/// for_immutable_mmap.activate(&mmap);
/// let mut another: VirtioDevice<&GuestMemoryMmap> =
///     VirtioDevice::new();
/// another.activate(&mmap);
/// # }
///
/// # #[cfg(all(feature = "backend-mmap", feature = "backend-atomic"))]
/// # fn test_2() {
/// // Using `VirtioDevice` with a mutable GuestMemoryMmap:
/// let mut for_mutable_mmap: VirtioDevice<GuestMemoryAtomic<GuestMemoryMmap>> =
///     VirtioDevice::new();
/// let atomic = GuestMemoryAtomic::new(get_mmap());
/// for_mutable_mmap.activate(atomic.clone());
/// let mut another: VirtioDevice<GuestMemoryAtomic<GuestMemoryMmap>> =
///     VirtioDevice::new();
/// another.activate(atomic.clone());
/// // atomic can be modified here...
/// # }
/// ```

pub trait GuestAddressSpace {
    /// The type that will be used to access guest memory.
    type M: GuestMemory;

    /// A type that provides access to the memory.
    type T: Clone + Deref<Target = Self::M>;

    /// Return an object (e.g. a reference or guard) that can be used
    /// to access memory through this address space.  The object provides
    /// a consistent snapshot of the memory map.
    fn memory(&self) -> Self::T;
}

impl<M: GuestMemory> GuestAddressSpace for &M {
    type T = Self;
    type M = M;

    fn memory(&self) -> Self {
        self
    }
}

impl<M: GuestMemory> GuestAddressSpace for Rc<M> {
    type T = Self;
    type M = M;

    fn memory(&self) -> Self {
        self.clone()
    }
}

impl<M: GuestMemory> GuestAddressSpace for Arc<M> {
    type T = Self;
    type M = M;

    fn memory(&self) -> Self {
        self.clone()
    }
}

/// GuestMemory represents a container for an *immutable* collection of
/// GuestMemoryRegion objects.  GuestMemory provides the `Bytes<GuestAddress>`
/// trait to hide the details of accessing guest memory by physical address.
/// Interior mutability is not allowed for implementations of GuestMemory so
/// that they always provide a consistent view of the memory map.
///
/// The task of the GuestMemory trait are:
/// - map a request address to a GuestMemoryRegion object and relay the request to it.
/// - handle cases where an access request spanning two or more GuestMemoryRegion objects.
pub trait GuestMemory {
    /// Type of objects hosted by the address space.
    type R: GuestMemoryRegion;

    /// Returns the number of regions in the collection.
    fn num_regions(&self) -> usize;

    /// Returns the region containing the specified address or `None`.
    fn find_region(&self, addr: GuestAddress) -> Option<&Self::R>;

    /// Perform the specified action on each region.
    ///
    /// It only walks children of current region and does not step into sub regions.
    fn with_regions<F, E>(&self, cb: F) -> std::result::Result<(), E>
    where
        F: Fn(usize, &Self::R) -> std::result::Result<(), E>;

    /// Perform the specified action on each region mutably.
    ///
    /// It only walks children of current region and does not step into sub regions.
    fn with_regions_mut<F, E>(&self, cb: F) -> std::result::Result<(), E>
    where
        F: FnMut(usize, &Self::R) -> std::result::Result<(), E>;

    /// Applies two functions, specified as callbacks, on the inner memory regions.
    ///
    /// # Arguments
    /// * `init` - Starting value of the accumulator for the `foldf` function.
    /// * `mapf` - "Map" function, applied to all the inner memory regions. It returns an array of
    ///            the same size as the memory regions array, containing the function's results
    ///            for each region.
    /// * `foldf` - "Fold" function, applied to the array returned by `mapf`. It acts as an
    ///             operator, applying itself to the `init` value and to each subsequent elemnent
    ///             in the array returned by `mapf`.
    ///
    /// # Examples
    ///
    /// * Compute the total size of all memory mappings in KB by iterating over the memory regions
    ///   and dividing their sizes to 1024, then summing up the values in an accumulator.
    ///
    /// ```
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::{GuestAddress, GuestMemory, GuestMemoryRegion, GuestMemoryMmap};
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// # fn test_map_fold() -> Result<(), ()> {
    ///     let start_addr1 = GuestAddress(0x0);
    ///     let start_addr2 = GuestAddress(0x400);
    ///     let mem = GuestMemoryMmap::from_ranges(&vec![(start_addr1, 1024), (start_addr2, 2048)])
    ///         .unwrap();
    ///     let total_size = mem.map_and_fold(
    ///         0,
    ///         |(_, region)| region.len() / 1024,
    ///         |acc, size| acc + size
    ///     );
    ///     println!("Total memory size = {} KB", total_size);
    ///     Ok(())
    /// # }
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// # test_map_fold();
    /// ```
    fn map_and_fold<F, G, T>(&self, init: T, mapf: F, foldf: G) -> T
    where
        F: Fn((usize, &Self::R)) -> T,
        G: Fn(T, T) -> T;

    /// Returns the maximum (inclusive) address managed by the
    /// [`GuestMemory`](trait.GuestMemory.html).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap};
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// # fn test_last_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemoryMmap::from_ranges(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     assert_eq!(start_addr.checked_add(0x3ff), Some(gm.last_addr()));
    ///     Ok(())
    /// # }
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// # test_last_addr();
    /// ```
    fn last_addr(&self) -> GuestAddress {
        self.map_and_fold(
            GuestAddress(0),
            |(_, region)| region.last_addr(),
            std::cmp::max,
        )
    }

    /// Tries to convert an absolute address to a relative address within the corresponding region.
    ///
    /// Returns `None` if `addr` isn't present within the memory of the guest.
    fn to_region_addr(&self, addr: GuestAddress) -> Option<(&Self::R, MemoryRegionAddress)> {
        self.find_region(addr)
            .map(|r| (r, r.to_region_addr(addr).unwrap()))
    }

    /// Returns `true` if the given address is present within the memory of the guest.
    fn address_in_range(&self, addr: GuestAddress) -> bool {
        self.find_region(addr).is_some()
    }

    /// Returns the given address if it is present within the memory of the guest.
    fn check_address(&self, addr: GuestAddress) -> Option<GuestAddress> {
        self.find_region(addr).map(|_| addr)
    }

    /// Returns the address plus the offset if it is present within the memory of the guest.
    fn checked_offset(&self, base: GuestAddress, offset: usize) -> Option<GuestAddress> {
        base.checked_add(offset as u64)
            .and_then(|addr| self.check_address(addr))
    }

    /// Invokes callback `f` to handle data in the address range `[addr, addr + count)`.
    ///
    /// /// The address range `[addr, addr + count)` may span more than one
    /// [`GuestMemoryRegion`](trait.GuestMemoryRegion.html) objects, or even have holes in it.
    /// So [`try_access()`](trait.GuestMemory.html#method.try_access) invokes the callback 'f'
    /// for each [`GuestMemoryRegion`](trait.GuestMemoryRegion.html) object involved and returns:
    /// - the error code returned by the callback 'f'
    /// - the size of the already handled data when encountering the first hole
    /// - the size of the already handled data when the whole range has been handled
    fn try_access<F>(&self, count: usize, addr: GuestAddress, mut f: F) -> Result<usize>
    where
        F: FnMut(usize, usize, MemoryRegionAddress, &Self::R) -> Result<usize>,
    {
        let mut cur = addr;
        let mut total = 0;
        while let Some(region) = self.find_region(cur) {
            let start = region.to_region_addr(cur).unwrap();
            let cap = region.len() - start.raw_value();
            let len = std::cmp::min(cap, (count - total) as GuestUsize);
            match f(total, len as usize, start, region) {
                // no more data
                Ok(0) => break,
                // made some progress
                Ok(len) => {
                    total += len;
                    if total == count {
                        break;
                    }
                    cur = match cur.overflowing_add(len as GuestUsize) {
                        (GuestAddress(0), _) => GuestAddress(0),
                        (result, false) => result,
                        (_, true) => panic!("guest address overflow"),
                    }
                }
                // error happened
                e => return e,
            }
        }
        if total == 0 {
            Err(Error::InvalidGuestAddress(addr))
        } else {
            Ok(total)
        }
    }

    /// Get the host virtual address corresponding to the guest address.
    ///
    /// Some [`GuestMemory`](trait.GuestMemory.html) implementations, like `GuestMemoryMmap`,
    /// have the capability to mmap the guest address range into virtual address space of the host
    /// for direct access, so the corresponding host virtual address may be passed to other
    /// subsystems.
    ///
    /// # Note
    /// The underlying guest memory is not protected from memory aliasing, which breaks the
    /// Rust memory safety model. It's the caller's responsibility to ensure that there's no
    /// concurrent accesses to the underlying guest memory.
    ///
    /// # Arguments
    /// * `guest_addr` - Guest address to convert.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// # fn test_get_host_address() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemoryMmap::from_ranges(&vec![(start_addr, 0x500)]).map_err(|_| ())?;
    ///     let addr = gm.get_host_address(GuestAddress(0x1200)).unwrap();
    ///     println!("Host address is {:p}", addr);
    ///     Ok(())
    /// # }
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// test_get_host_address();
    /// ```
    fn get_host_address(&self, addr: GuestAddress) -> Result<*mut u8> {
        self.to_region_addr(addr)
            .ok_or_else(|| Error::InvalidGuestAddress(addr))
            .and_then(|(r, addr)| r.get_host_address(addr))
    }

    /// Returns a [`VolatileSlice`](struct.VolatileSlice.html) of `count` bytes starting at
    /// `addr`.
    fn get_slice(
        &self,
        addr: GuestAddress,
        count: usize,
    ) -> Result<volatile_memory::VolatileSlice> {
        self.to_region_addr(addr)
            .ok_or_else(|| Error::InvalidGuestAddress(addr))
            .and_then(|(r, addr)| r.get_slice(addr, count))
    }
}

impl<T: GuestMemory> Bytes<GuestAddress> for T {
    type E = Error;

    fn write(&self, buf: &[u8], addr: GuestAddress) -> Result<usize> {
        self.try_access(
            buf.len(),
            addr,
            |offset, _count, caddr, region| -> Result<usize> {
                region.write(&buf[offset as usize..], caddr)
            },
        )
    }

    fn read(&self, buf: &mut [u8], addr: GuestAddress) -> Result<usize> {
        self.try_access(
            buf.len(),
            addr,
            |offset, _count, caddr, region| -> Result<usize> {
                region.read(&mut buf[offset as usize..], caddr)
            },
        )
    }

    /// # Examples
    /// * Write a slice at guestaddress 0x200.
    ///
    /// ```
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::{Bytes, GuestAddress, mmap::GuestMemoryMmap};
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// # fn test_write_u64() {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm =
    ///             GuestMemoryMmap::from_ranges(&vec![(start_addr, 0x400)])
    ///             .expect("Could not create guest memory");
    ///     let res = gm.write_slice(&[1, 2, 3, 4, 5], start_addr);
    ///     assert!(res.is_ok());
    /// # }
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// # test_write_u64();
    /// ```
    fn write_slice(&self, buf: &[u8], addr: GuestAddress) -> Result<()> {
        let res = self.write(buf, addr)?;
        if res != buf.len() {
            return Err(Error::PartialBuffer {
                expected: buf.len(),
                completed: res,
            });
        }
        Ok(())
    }

    /// # Examples
    /// * Read a slice of length 16 at guestaddress 0x200.
    ///
    /// ```
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::{Bytes, GuestAddress, mmap::GuestMemoryMmap};
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// # fn test_write_u64() {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm =
    ///             GuestMemoryMmap::from_ranges(&vec![(start_addr, 0x400)])
    ///             .expect("Could not create guest memory");
    ///     let buf = &mut [0u8; 16];
    ///     let res = gm.read_slice(buf, start_addr);
    ///     assert!(res.is_ok());
    /// # }
    ///
    /// # #[cfg(feature = "backend-mmap")]
    /// # test_write_u64()
    /// ```
    fn read_slice(&self, buf: &mut [u8], addr: GuestAddress) -> Result<()> {
        let res = self.read(buf, addr)?;
        if res != buf.len() {
            return Err(Error::PartialBuffer {
                expected: buf.len(),
                completed: res,
            });
        }
        Ok(())
    }

    /// # Examples
    ///
    /// * Read bytes from /dev/urandom
    ///
    /// ```
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::{Address, Bytes, GuestAddress, mmap::GuestMemoryMmap};
    /// # use std::fs::File;
    /// # use std::path::Path;
    ///
    /// # #[cfg(all(unix, feature = "backend-mmap"))]
    /// # fn test_read_random() {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let gm =
    ///         GuestMemoryMmap::from_ranges(&vec![(start_addr, 0x400)])
    ///         .expect("Could not create guest memory");
    ///     let mut file = File::open(Path::new("/dev/urandom"))
    ///         .expect("could not open /dev/urandom");
    ///     let addr = GuestAddress(0x1010);
    ///     gm.read_from(addr, &mut file, 128)
    ///         .expect("Could not read from /dev/urandom into guest memory");
    ///     let read_addr = addr.checked_add(8).expect("Could not compute read address");
    ///     let rand_val: u32 = gm
    ///         .read_obj(read_addr)
    ///         .expect("Could not read u32 val from /dev/urandom");
    /// # }
    ///
    /// # #[cfg(all(unix, feature = "backend-mmap"))]
    /// # test_read_random();
    /// ```
    fn read_from<F>(&self, addr: GuestAddress, src: &mut F, count: usize) -> Result<usize>
    where
        F: Read,
    {
        self.try_access(count, addr, |offset, len, caddr, region| -> Result<usize> {
            // Check if something bad happened before doing unsafe things.
            assert!(offset < count);
            if let Some(dst) = unsafe { region.as_mut_slice() } {
                // This is safe cause `start` and `len` are within the `region`.
                let start = caddr.raw_value() as usize;
                let end = start + len;
                loop {
                    match src.read(&mut dst[start..end]) {
                        Ok(n) => break Ok(n),
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => break Err(Error::IOError(e)),
                    }
                }
            } else {
                let len = std::cmp::min(len, MAX_ACCESS_CHUNK);
                let mut buf = vec![0u8; len].into_boxed_slice();
                loop {
                    match src.read(&mut buf[..]) {
                        Ok(bytes_read) => {
                            let bytes_written = region.write(&buf[0..bytes_read], caddr)?;
                            assert_eq!(bytes_written, bytes_read);
                            break Ok(bytes_read);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => break Err(Error::IOError(e)),
                    }
                }
            }
        })
    }

    fn read_exact_from<F>(&self, addr: GuestAddress, src: &mut F, count: usize) -> Result<()>
    where
        F: Read,
    {
        let res = self.read_from(addr, src, count)?;
        if res != count {
            return Err(Error::PartialBuffer {
                expected: count,
                completed: res,
            });
        }
        Ok(())
    }

    /// # Examples
    ///
    /// * Write 128 bytes to /dev/null
    ///
    /// ```
    /// # #[cfg(feature = "backend-mmap")]
    /// # use vm_memory::{Bytes, GuestAddress, mmap::GuestMemoryMmap};
    /// # use std::fs::OpenOptions;
    /// # use std::path::Path;
    ///
    /// # #[cfg(all(unix, feature = "backend-mmap"))]
    /// # fn test_write_null() {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let gm =
    ///         GuestMemoryMmap::from_ranges(&vec![(start_addr, 1024)])
    ///         .expect("Could not create guest memory");
    ///     let mut file = OpenOptions::new()
    ///         .write(true)
    ///         .open("/dev/null")
    ///         .expect("Could not open /dev/null");
    ///
    ///     gm.write_to(start_addr, &mut file, 128)
    ///         .expect("Could not write 128 bytes to the provided address");
    /// # }
    ///
    /// # #[cfg(all(unix, feature = "backend-mmap"))]
    /// # test_write_null();
    /// ```
    fn write_to<F>(&self, addr: GuestAddress, dst: &mut F, count: usize) -> Result<usize>
    where
        F: Write,
    {
        self.try_access(count, addr, |offset, len, caddr, region| -> Result<usize> {
            // Check if something bad happened before doing unsafe things.
            assert!(offset < count);
            if let Some(src) = unsafe { region.as_slice() } {
                // This is safe cause `start` and `len` are within the `region`.
                let start = caddr.raw_value() as usize;
                let end = start + len;
                loop {
                    // It is safe to read from volatile memory. Accessing the guest
                    // memory as a slice should be OK as long as nothing assumes another
                    // thread won't change what is loaded; however, we may want to introduce
                    // VolatileRead and VolatileWrite traits in the future.
                    match dst.write(&src[start..end]) {
                        Ok(n) => break Ok(n),
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => break Err(Error::IOError(e)),
                    }
                }
            } else {
                let len = std::cmp::min(len, MAX_ACCESS_CHUNK);
                let mut buf = vec![0u8; len].into_boxed_slice();
                let bytes_read = region.read(&mut buf, caddr)?;
                assert_eq!(bytes_read, len);
                // For a non-RAM region, reading could have side effects, so we
                // must use write_all().
                dst.write_all(&buf).map_err(Error::IOError)?;
                Ok(len)
            }
        })
    }

    fn write_all_to<F>(&self, addr: GuestAddress, dst: &mut F, count: usize) -> Result<()>
    where
        F: Write,
    {
        let res = self.write_to(addr, dst, count)?;
        if res != count {
            return Err(Error::PartialBuffer {
                expected: count,
                completed: res,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "backend-mmap")]
    use crate::{GuestAddress, GuestMemoryMmap};
    #[cfg(feature = "backend-mmap")]
    use std::io::Cursor;
    use vmm_sys_util::tempfile::TempFile;

    #[cfg(feature = "backend-mmap")]
    fn make_image(size: u8) -> Vec<u8> {
        let mut image: Vec<u8> = Vec::with_capacity(size as usize);
        for i in 0..size {
            image.push(i);
        }
        image
    }

    #[test]
    fn test_file_offset() {
        let file = TempFile::new().unwrap().into_file();
        let start = 1234;
        let file_offset = FileOffset::new(file, start);
        assert_eq!(file_offset.start(), start);
        assert_eq!(
            file_offset.file() as *const File,
            file_offset.arc().as_ref() as *const File
        );
    }

    #[cfg(feature = "backend-mmap")]
    #[test]
    fn checked_read_from() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x40);
        let mem = GuestMemoryMmap::from_ranges(&[(start_addr1, 64), (start_addr2, 64)]).unwrap();
        let image = make_image(0x80);
        let offset = GuestAddress(0x30);
        let count: usize = 0x20;
        assert_eq!(
            0x20 as usize,
            mem.read_from(offset, &mut Cursor::new(&image), count)
                .unwrap()
        );
    }
}

//! Types for I/O buffers.
//!
//! This module provides:
//! - buffer types that can be allocated with arbitrary alignment,
//! - references to buffers that more or less ensure the content is read only once (because it can
//!   change for buffers owned by VM guests),
//! - buffer vector types.

use crate::macros::passthrough_trait_fn;
#[cfg(feature = "vm-memory")]
use crate::misc_helpers::ImagoAsRef;
use std::alloc::{self, GlobalAlloc};
use std::fmt::{self, Debug, Formatter};
use std::io::{IoSlice, IoSliceMut};
use std::marker::PhantomData;
#[cfg(unix)]
use std::mem;
use std::mem::{size_of, size_of_val};
use std::ops::Range;
use std::{cmp, io, ptr, slice};

/// Owned memory buffer.
pub struct IoBuffer {
    /// Raw pointer to the start of the buffer.
    pointer: *mut u8,

    /// Size in bytes.
    size: usize,

    /// Allocation layout.  `None` only for null buffers.
    layout: Option<alloc::Layout>,
}

/// Reference to any immutable memory buffer.
pub struct IoBufferRef<'a> {
    /// Raw pointer to the start of the buffer.
    pointer: *const u8,

    /// Size in bytes.
    size: usize,

    /// Lifetime marker.
    _lifetime: PhantomData<&'a [u8]>,
}

/// Reference to any mutable memory buffer.
pub struct IoBufferMut<'a> {
    /// Raw pointer to the start of the buffer.
    pointer: *mut u8,

    /// Size in bytes.
    size: usize,

    /// Lifetime marker.
    _lifetime: PhantomData<&'a mut [u8]>,
}

// Blocked because of the pointer, but we want this to be usable across threads
unsafe impl Send for IoBuffer {}
unsafe impl Sync for IoBuffer {}
unsafe impl Send for IoBufferRef<'_> {}
unsafe impl Sync for IoBufferRef<'_> {}
unsafe impl Send for IoBufferMut<'_> {}
unsafe impl Sync for IoBufferMut<'_> {}

impl IoBuffer {
    /// Create a new owned buffer, containing uninitialized data.
    ///
    /// Do note that the returned buffer contains uninitialized data, which however is perfectly
    /// fine for an I/O buffer.
    pub fn new(size: usize, alignment: usize) -> io::Result<Self> {
        let layout = alloc::Layout::from_size_align(size, alignment).map_err(io::Error::other)?;
        Self::new_with_layout(layout)
    }

    /// Create a new owned buffer, containing uninitialized data, with the given `layout`.
    pub fn new_with_layout(layout: alloc::Layout) -> io::Result<Self> {
        if layout.size() == 0 {
            return Ok(IoBuffer {
                pointer: ptr::null_mut(),
                size: 0,
                layout: None,
            });
        }

        // We guarantee the size not to be 0 and do not care about the memory being uninitialized,
        // so this is safe
        let pointer = unsafe { alloc::System.alloc(layout) };

        if pointer.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!(
                    "Failed to allocate memory (size={}, alignment={})",
                    layout.size(),
                    layout.align(),
                ),
            ));
        }

        Ok(IoBuffer {
            pointer,
            size: layout.size(),
            layout: Some(layout),
        })
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Whether this is a null buffer (length is 0).
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Generate an immutable reference.
    pub fn as_ref(&self) -> IoBufferRef<'_> {
        IoBufferRef {
            pointer: self.pointer as *const u8,
            size: self.size,
            _lifetime: PhantomData,
        }
    }

    /// Generate an immutable reference to a sub-range.
    pub fn as_ref_range(&self, range: Range<usize>) -> IoBufferRef<'_> {
        IoBufferRef::from_slice(&self.as_ref().into_slice()[range])
    }

    /// Generate a mutable reference.
    pub fn as_mut(&mut self) -> IoBufferMut<'_> {
        IoBufferMut {
            pointer: self.pointer,
            size: self.size,
            _lifetime: PhantomData,
        }
    }

    /// Generate a mutable reference to a sub-range.
    pub fn as_mut_range(&mut self, range: Range<usize>) -> IoBufferMut<'_> {
        (&mut self.as_mut().into_slice()[range]).into()
    }
}

impl Drop for IoBuffer {
    /// Free this buffer.
    fn drop(&mut self) {
        if let Some(layout) = self.layout {
            // Safe because we have allocated this buffer using `alloc::System`
            unsafe {
                alloc::System.dealloc(self.pointer, layout);
            }
        }
    }
}

/// Common functions for both `IoBufferRef` and `IoBufferMut`.
pub trait IoBufferRefTrait<'a>: Sized {
    /// `&[T]` or `&mut [T]`.
    type SliceType<T: Copy + Sized + 'a>;

    /// `*const T` or `*mut T`.
    type PointerType<T: Copy + Sized + 'a>;

    /// Create a reference to a slice.
    fn from_slice(slice: Self::SliceType<u8>) -> Self;

    /// Create an owned [`IoBuffer`] with the same data (copied).
    fn try_into_owned(self, alignment: usize) -> io::Result<IoBuffer>;

    /// Size in bytes.
    fn len(&self) -> usize;

    /// Whether the length is 0.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the pointer to the start of the buffer.
    fn as_ptr(&self) -> Self::PointerType<u8>;

    /// Turn this reference into a slice.
    ///
    /// References to `IoBuffer`s must not be copied/cloned (so they can only be accessed once;
    /// they are considered volatile due to potential VM guest accesses), so this consumes the
    /// object.
    fn into_slice(self) -> Self::SliceType<u8> {
        // Alignment requirement is always met, resulting data is pure binary data
        unsafe { self.into_typed_slice::<u8>() }
    }

    /// Turn this reference into a slice with the given element type.
    ///
    /// # Safety
    /// Caller must ensure that alignment and length requirements are met and that the resulting
    /// data is valid.
    unsafe fn into_typed_slice<T: Copy + Sized>(self) -> Self::SliceType<T>;

    /// Split the buffer at `mid`.
    ///
    /// Return `&self[..mid]` and `&self[mid..]`.
    ///
    /// If `mid > self.len()`, return `&self[..]` and `[]`.
    fn split_at(self, mid: usize) -> (Self, Self);

    /// Make this reference immutable.
    fn into_ref(self) -> IoBufferRef<'a>;
}

impl<'a> IoBufferRef<'a> {
    /// Create a reference to a slice.
    pub fn from_slice(slice: &'a [u8]) -> Self {
        IoBufferRef {
            pointer: slice.as_ptr(),
            size: size_of_val(slice),
            _lifetime: PhantomData,
        }
    }

    /// Create an owned [`IoBuffer`] with the same data (copied).
    pub fn try_into_owned(self, alignment: usize) -> io::Result<IoBuffer> {
        let mut new_buf = IoBuffer::new(self.len(), alignment)?;
        new_buf
            .as_mut()
            .into_slice()
            .copy_from_slice(self.into_slice());
        Ok(new_buf)
    }

    /// Size in bytes.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Whether the length is 0.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the pointer to the start of the buffer.
    pub fn as_ptr(&self) -> *const u8 {
        self.pointer
    }

    /// Turn this reference into a slice.
    ///
    /// References to `IoBuffer`s must not be copied/cloned (so they can only be accessed once;
    /// they are considered volatile due to potential VM guest accesses), so this consumes the
    /// object.
    pub fn into_slice(self) -> &'a [u8] {
        // Alignment requirement is always met, resulting data is pure binary data
        unsafe { self.into_typed_slice::<u8>() }
    }

    /// Turn this reference into a slice with the given element type.
    ///
    /// # Safety
    /// Caller must ensure that alignment and length requirements are met and that the resulting
    /// data is valid.
    pub unsafe fn into_typed_slice<T: Copy + Sized>(self) -> &'a [T] {
        // Safety ensured by the caller; we ensure that nothing outside of this buffer will be part
        // of the slice
        unsafe { slice::from_raw_parts(self.as_ptr() as *const T, self.len() / size_of::<T>()) }
    }

    /// Split the buffer at `mid`.
    ///
    /// Return `&self[..mid]` and `&self[mid..]`.
    ///
    /// If `mid > self.len()`, return `&self[..]` and `[]`.
    pub fn split_at(self, mid: usize) -> (IoBufferRef<'a>, IoBufferRef<'a>) {
        let head_len = cmp::min(mid, self.size);

        (
            IoBufferRef {
                pointer: self.pointer,
                size: head_len,
                _lifetime: PhantomData,
            },
            IoBufferRef {
                // Safe because we have limited this to `self.size`
                pointer: unsafe { self.pointer.add(head_len) },
                size: self.size - head_len,
                _lifetime: PhantomData,
            },
        )
    }

    /// Make this reference immutable.
    pub fn into_ref(self) -> IoBufferRef<'a> {
        self
    }
}

impl<'a> IoBufferRefTrait<'a> for IoBufferRef<'a> {
    type SliceType<T: Copy + Sized + 'a> = &'a [T];
    type PointerType<T: Copy + Sized + 'a> = *const T;

    passthrough_trait_fn! { fn from_slice(slice: Self::SliceType<u8>) -> Self; }
    passthrough_trait_fn! { fn try_into_owned(self, alignment: usize) -> io::Result<IoBuffer>; }
    passthrough_trait_fn! { fn len(&self) -> usize; }
    passthrough_trait_fn! { fn as_ptr(&self) -> Self::PointerType<u8>; }
    passthrough_trait_fn! { fn split_at(self, mid: usize) -> (Self, Self); }
    passthrough_trait_fn! { fn into_ref(self) -> IoBufferRef<'a>; }

    unsafe fn into_typed_slice<T: Copy + Sized>(self) -> Self::SliceType<T> {
        Self::into_typed_slice(self)
    }
}

impl<'a> From<IoSlice<'a>> for IoBufferRef<'a> {
    fn from(slice: IoSlice<'a>) -> Self {
        IoBufferRef {
            pointer: slice.as_ptr(),
            size: slice.len(),
            _lifetime: PhantomData,
        }
    }
}

impl<'a> From<IoBufferRef<'a>> for IoSlice<'a> {
    fn from(buf: IoBufferRef<'a>) -> Self {
        IoSlice::new(buf.into_slice())
    }
}

impl<'a> IoBufferMut<'a> {
    /// Create a reference to a slice.
    pub fn from_slice(slice: &'a mut [u8]) -> Self {
        IoBufferMut {
            pointer: slice.as_mut_ptr(),
            size: size_of_val(slice),
            _lifetime: PhantomData,
        }
    }

    /// Create an owned [`IoBuffer`] with the same data (copied).
    pub fn try_into_owned(self, alignment: usize) -> io::Result<IoBuffer> {
        let mut new_buf = IoBuffer::new(self.len(), alignment)?;
        new_buf
            .as_mut()
            .into_slice()
            .copy_from_slice(self.into_slice());
        Ok(new_buf)
    }

    /// Size in bytes.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Whether the length is 0.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the pointer to the start of the buffer.
    pub fn as_ptr(&self) -> *mut u8 {
        self.pointer
    }

    /// Turn this reference into a slice.
    ///
    /// References to `IoBuffer`s must not be copied/cloned (so they can only be accessed once;
    /// they are considered volatile due to potential VM guest accesses), so this consumes the
    /// object.
    pub fn into_slice(self) -> &'a mut [u8] {
        // Alignment requirement is always met, resulting data is pure binary data
        unsafe { self.into_typed_slice::<u8>() }
    }

    /// Turn this reference into a slice with the given element type.
    ///
    /// # Safety
    /// Caller must ensure that alignment and length requirements are met and that the resulting
    /// data is valid.
    pub unsafe fn into_typed_slice<T: Copy + Sized>(self) -> &'a mut [T] {
        // Safety ensured by the caller; we ensure that nothing outside of this buffer will be part
        // of the slice
        unsafe { slice::from_raw_parts_mut(self.as_ptr() as *mut T, self.len() / size_of::<T>()) }
    }

    /// Split the buffer at `mid`.
    ///
    /// Return `&self[..mid]` and `&self[mid..]`.
    ///
    /// If `mid > self.len()`, return `&self[..]` and `[]`.
    pub fn split_at(self, mid: usize) -> (IoBufferMut<'a>, IoBufferMut<'a>) {
        let head_len = cmp::min(mid, self.size);

        (
            IoBufferMut {
                pointer: self.pointer,
                size: head_len,
                _lifetime: PhantomData,
            },
            IoBufferMut {
                // Safe because we have limited this to `self.size`
                pointer: unsafe { self.pointer.add(head_len) },
                size: self.size - head_len,
                _lifetime: PhantomData,
            },
        )
    }

    /// Make this reference immutable.
    pub fn into_ref(self) -> IoBufferRef<'a> {
        IoBufferRef {
            pointer: self.pointer,
            size: self.size,
            _lifetime: PhantomData,
        }
    }
}

impl<'a> IoBufferRefTrait<'a> for IoBufferMut<'a> {
    type SliceType<T: Copy + Sized + 'a> = &'a mut [T];
    type PointerType<T: Copy + Sized + 'a> = *mut T;

    passthrough_trait_fn! { fn from_slice(slice: Self::SliceType<u8>) -> Self; }
    passthrough_trait_fn! { fn try_into_owned(self, alignment: usize) -> io::Result<IoBuffer>; }
    passthrough_trait_fn! { fn len(&self) -> usize; }
    passthrough_trait_fn! { fn as_ptr(&self) -> Self::PointerType<u8>; }
    passthrough_trait_fn! { fn split_at(self, mid: usize) -> (Self, Self); }
    passthrough_trait_fn! { fn into_ref(self) -> IoBufferRef<'a>; }

    unsafe fn into_typed_slice<T: Copy + Sized>(self) -> Self::SliceType<T> {
        Self::into_typed_slice(self)
    }
}

impl<'a, T: Sized> From<&'a mut [T]> for IoBufferMut<'a> {
    fn from(slice: &'a mut [T]) -> Self {
        IoBufferMut {
            pointer: slice.as_mut_ptr() as *mut u8,
            size: size_of_val(slice),
            _lifetime: PhantomData,
        }
    }
}

impl<'a> From<IoSliceMut<'a>> for IoBufferMut<'a> {
    fn from(mut slice: IoSliceMut<'a>) -> Self {
        IoBufferMut {
            pointer: slice.as_mut_ptr(),
            size: slice.len(),
            _lifetime: PhantomData,
        }
    }
}

impl<'a> From<IoBufferMut<'a>> for IoSliceMut<'a> {
    fn from(buf: IoBufferMut<'a>) -> Self {
        IoSliceMut::new(buf.into_slice())
    }
}

/// Common functions for both `IoVector` and `IoVectorMut`.
#[allow(dead_code)]
pub(crate) trait IoVectorTrait: Sized {
    /// `&[u8]` or `&mut [u8]`.
    type SliceType;

    /// `IoSlice` or `IoSliceMut`.
    type BufferType;

    /// Create an empty vector.
    fn new() -> Self;

    /// Create an empty vector, pre-allocating space for `cap` buffers.
    ///
    /// This does not allocate an memory buffer, only space in the buffer vector.
    fn with_capacity(cap: usize) -> Self;

    /// Append a slice.
    fn push(&mut self, slice: Self::SliceType);

    /// Append a slice.
    fn push_ioslice(&mut self, ioslice: Self::BufferType);

    /// Insert a slice at the given `index` in the buffer vector.
    fn insert(&mut self, index: usize, slice: Self::SliceType);

    /// Return the sum total length in bytes of all buffers in this vector.
    fn len(&self) -> u64;

    /// Return the number of buffers in this vector.
    fn buffer_count(&self) -> usize;

    /// Return `true` if and only if this vector’s length is zero.
    ///
    /// Synonymous with whether this vector’s buffer count is zero.
    fn is_empty(&self) -> bool {
        debug_assert!((self.len() == 0) == (self.buffer_count() == 0));
        self.len() == 0
    }

    /// Append all buffers from the given other vector to this vector.
    fn append(&mut self, other: Self);

    /// Split the vector into two.
    ///
    /// The first returned vector contains the bytes in the `[..mid]` range, and the second one
    /// covers the `[mid..]` range.
    fn split_at(self, mid: u64) -> (Self, Self);

    /// Like [`IoVectorTrait::split_at()`], but discards the head, only returning the tail.
    ///
    /// More efficient than to use `self.split_at(mid).1` because the former requires creating a
    /// new `Vec` object for the head, which this version skips.
    fn split_tail_at(self, mid: u64) -> Self;

    /// Copy the data from `self` into `slice`.
    ///
    /// Both must have the same length.
    fn copy_into_slice(&self, slice: &mut [u8]);

    /// Create a single owned [`IoBuffer`] with the same data (copied).
    fn try_into_owned(self, alignment: usize) -> io::Result<IoBuffer>;

    /// Return a corresponding `&[libc::iovec]`.
    ///
    /// # Safety
    /// `iovec` has no lifetime information.  Callers must ensure no elements in the returned slice
    /// are used beyond the lifetime `'_`.
    #[cfg(unix)]
    unsafe fn as_iovec<'a>(&'a self) -> &'a [libc::iovec]
    where
        Self: 'a;

    /// Check whether `self` is aligned.
    ///
    /// Each buffer must be aligned to `mem_alignment`, and each buffer’s length must be aligned to
    /// both `mem_alignment` and `req_alignment` (the I/O request offset/size alignment).
    fn is_aligned(&self, mem_alignment: usize, req_alignment: usize) -> bool;

    /// Return the internal vector of `IoSlice` objects.
    fn into_inner(self) -> Vec<Self::BufferType>;
}

/// Implement most of both `IoVector` and `IoVectorMut`.
macro_rules! impl_io_vector {
    ($type:tt, $inner_type:tt, $buffer_type:tt, $slice_type:ty, $slice_type_lifetime_b:ty) => {
        /// Vector of memory buffers.
        pub struct $type<'a> {
            /// Buffer list.
            vector: Vec<$inner_type<'a>>,

            /// Complete size in bytes.
            total_size: u64,
        }

        impl<'a> $type<'a> {
            /// Create an empty vector.
            pub fn new() -> Self {
                Self::default()
            }

            /// Create an empty vector, pre-allocating space for `cap` buffers.
            ///
            /// This does not allocate an memory buffer, only space in the buffer vector.
            pub fn with_capacity(cap: usize) -> Self {
                $type {
                    vector: Vec::with_capacity(cap),
                    total_size: 0,
                }
            }

            /// Append a slice.
            pub fn push(&mut self, slice: $slice_type) {
                debug_assert!(!slice.is_empty());
                self.total_size += slice.len() as u64;
                self.vector.push($inner_type::new(slice));
            }

            /// Append a slice.
            pub fn push_ioslice(&mut self, ioslice: $inner_type<'a>) {
                debug_assert!(!ioslice.is_empty());
                self.total_size += ioslice.len() as u64;
                self.vector.push(ioslice);
            }

            /// Insert a slice at the given `index` in the buffer vector.
            pub fn insert(&mut self, index: usize, slice: $slice_type) {
                debug_assert!(!slice.is_empty());
                self.total_size += slice.len() as u64;
                self.vector.insert(index, $inner_type::new(slice));
            }

            /// Return the sum total length in bytes of all buffers in this vector.
            pub fn len(&self) -> u64 {
                self.total_size
            }

            /// Return the number of buffers in this vector.
            pub fn buffer_count(&self) -> usize {
                self.vector.len()
            }

            /// Return `true` if and only if this vector’s length is zero.
            ///
            /// Synonymous with whether this vector’s buffer count is zero.
            pub fn is_empty(&self) -> bool {
                debug_assert!((self.len() == 0) == (self.buffer_count() == 0));
                self.len() == 0
            }

            /// Append all buffers from the given other vector to this vector.
            pub fn append(&mut self, mut other: Self) {
                self.total_size += other.total_size;
                self.vector.append(&mut other.vector);
            }

            /// Split the vector into two.
            ///
            /// The first returned vector contains the bytes in the `[..mid]` range, and the second
            /// one covers the `[mid..]` range.
            pub fn split_at(self, mid: u64) -> (Self, Self) {
                let (head, tail) = self.do_split_at(mid, true);
                (head.unwrap(), tail)
            }

            /// Like [`Self::split_at()`], but discards the head, only returning the tail.
            ///
            /// More efficient than to use `self.split_at(mid).1` because the former requires
            /// creating a new `Vec` object for the head, which this version skips.
            pub fn split_tail_at(self, mid: u64) -> Self {
                self.do_split_at(mid, false).1
            }

            /// Copy the data from `self` into `slice`.
            ///
            /// Both must have the same length.
            pub fn copy_into_slice(&self, slice: &mut [u8]) {
                if slice.len() as u64 != self.total_size {
                    panic!("IoVectorTrait::copy_into_slice() called on a slice of different length from the vector");
                }

                assert!(self.total_size <= usize::MAX as u64);

                let mut offset = 0usize;
                for elem in self.vector.iter() {
                    let next_offset = offset + elem.len();
                    slice[offset..next_offset].copy_from_slice(&elem[..]);
                    offset = next_offset;
                }
            }

            /// Create a single owned [`IoBuffer`] with the same data (copied).
            pub fn try_into_owned(self, alignment: usize) -> io::Result<IoBuffer> {
                let size = self.total_size.try_into().map_err(|_| {
                    io::Error::other(format!("Buffer is too big ({})", self.total_size))
                })?;
                let mut new_buf = IoBuffer::new(size, alignment)?;
                self.copy_into_slice(new_buf.as_mut().into_slice());
                Ok(new_buf)
            }

            /// Return a corresponding `&[libc::iovec]`.
            ///
            /// # Safety
            /// `iovec` has no lifetime information.  Callers must ensure no elements in the
            /// returned slice are used beyond the lifetime `'_`.
            #[cfg(unix)]
            pub unsafe fn as_iovec<'b>(&'b self) -> &'b [libc::iovec] where Self: 'b {
                // IoSlice and IoSliceMut are defined to have the same representation in memory as
                // libc::iovec does
                unsafe {
                    mem::transmute::<&'b [$inner_type<'b>], &'b [libc::iovec]>(&self.vector[..])
                }
            }

            /// Check whether `self` is aligned.
            ///
            /// Each buffer must be aligned to `mem_alignment`, and each buffer’s length must be
            /// aligned to both `mem_alignment` and `req_alignment` (the I/O request offset/size
            /// alignment).
            pub fn is_aligned(&self, mem_alignment: usize, req_alignment: usize) -> bool {
                // Trivial case
                if mem_alignment == 1 && req_alignment == 1 {
                    return true;
                }

                debug_assert!(mem_alignment.is_power_of_two() && req_alignment.is_power_of_two());
                let base_align_mask = mem_alignment - 1;
                let len_align_mask = base_align_mask | (req_alignment - 1);

                self.vector.iter().all(|buf| {
                    buf.as_ptr() as usize & base_align_mask == 0 &&
                        buf.len() & len_align_mask == 0
                })
            }

            /// Return the internal vector of `IoSlice` objects.
            pub fn into_inner(self) -> Vec<$inner_type<'a>> {
                self.vector
            }

            /// Same as [`Self::push()`], but takes ownership of `self`.
            ///
            /// By taking ownership of `self` and returning it, this method allows reducing the
            /// lifetime of `self` to that of `slice`, if necessary.
            pub fn with_pushed<'b>(self, slice: $slice_type_lifetime_b) -> $type<'b>
            where
                'a: 'b,
            {
                let mut vec: $type<'b> = self;
                vec.push(slice);
                vec
            }

            /// Same as [`Self::insert()`], but takes ownership of `self.`
            ///
            /// By taking ownership of `self` and returning it, this method allows reducing the
            /// lifetime of `self` to that of `slice`, if necessary.
            pub fn with_inserted<'b>(self, index: usize, slice: $slice_type_lifetime_b) -> $type<'b>
            where
                'a: 'b,
            {
                let mut vec: $type<'b> = self;
                vec.insert(index, slice);
                vec
            }

            /// Implementation for [`Self::split_at()`] and [`Self::split_tail_at()`].
            ///
            /// If `keep_head` is true, both head and tail are returned ([`Self::split_at()`]).
            /// Otherwise, the head is discarded ([`Self::split_tail_at()`]).
            fn do_split_at(mut self, mid: u64, keep_head: bool) -> (Option<$type<'a>>, $type<'a>) {
                if mid >= self.total_size {
                    // Special case: Empty tail
                    return (
                        keep_head.then_some(self),
                        $type {
                            vector: Vec::new(),
                            total_size: 0,
                        },
                    );
                }

                let mut i = 0; // Current element index
                let mut offset = 0u64; // Current element offset
                let (vec_head, vec_tail) = loop {
                    if offset == mid {
                        // Clean split: `i` is fully behind `mid`, the rest is fully ahead
                        if keep_head {
                            let mut vec_head = self.vector;
                            let vec_tail = vec_head.split_off(i);
                            break (Some(vec_head), vec_tail);
                        } else {
                            break (None, self.vector.split_off(i));
                        }
                    }

                    let post_elm_offset = offset + self.vector[i].len() as u64;

                    if post_elm_offset > mid {
                        // Not so clean split: The beginning of this element was before `mid`, the end is
                        // behind it, so we must split this element between head and tail
                        let mut vec_head = self.vector;
                        let mut tail_iter = vec_head.drain(i..);

                        // This is the current element (at `i`), which must be present
                        let mid_elm = tail_iter.next().unwrap();
                        let mid_elm: $buffer_type<'a> = mid_elm.into();

                        // Each element's length is of type usize, so this must fit into usize
                        let mid_elm_head_len: usize = (mid - offset).try_into().unwrap();
                        let (mid_head, mid_tail) = mid_elm.split_at(mid_elm_head_len);

                        let mut vec_tail: Vec<$inner_type<'a>> = vec![mid_tail.into()];
                        vec_tail.extend(tail_iter);

                        if keep_head {
                            vec_head.push(mid_head.into());
                            break (Some(vec_head), vec_tail);
                        } else {
                            break (None, vec_tail);
                        }
                    }

                    offset = post_elm_offset;

                    i += 1;
                    // We know that `mid < self.total_size`, so we must encounter `mid before the end of
                    // the vector
                    assert!(i < self.vector.len());
                };

                let head = keep_head.then(|| $type {
                    vector: vec_head.unwrap(),
                    total_size: mid,
                });
                let tail = $type {
                    vector: vec_tail,
                    total_size: self.total_size - mid,
                };

                (head, tail)
            }
        }

        impl<'a> IoVectorTrait for $type<'a> {
            type SliceType = $slice_type;
            type BufferType = $inner_type<'a>;

            passthrough_trait_fn! { fn new() -> Self; }
            passthrough_trait_fn! { fn with_capacity(cap: usize) -> Self; }
            passthrough_trait_fn! { fn push(&mut self, slice: Self::SliceType); }
            passthrough_trait_fn! { fn push_ioslice(&mut self, ioslice: Self::BufferType); }
            passthrough_trait_fn! { fn insert(&mut self, index: usize, slice: Self::SliceType); }
            passthrough_trait_fn! { fn len(&self) -> u64; }
            passthrough_trait_fn! { fn buffer_count(&self) -> usize; }
            passthrough_trait_fn! { fn append(&mut self, other: Self); }
            passthrough_trait_fn! { fn split_at(self, mid: u64) -> (Self, Self); }
            passthrough_trait_fn! { fn split_tail_at(self, mid: u64) -> Self; }
            passthrough_trait_fn! { fn copy_into_slice(&self, slice: &mut [u8]); }
            passthrough_trait_fn! { fn try_into_owned(self, alignment: usize) -> io::Result<IoBuffer>; }
            passthrough_trait_fn! { fn is_aligned(&self, mem_alignment: usize, req_alignment: usize) -> bool; }
            passthrough_trait_fn! { fn into_inner(self) -> Vec<Self::BufferType>; }

            #[cfg(unix)]
            unsafe fn as_iovec<'b>(&'b self) -> &'b [libc::iovec]
            where
                Self: 'b
            {
                Self::as_iovec(self)
            }
        }

        impl<'a> From<Vec<$inner_type<'a>>> for $type<'a> {
            fn from(vector: Vec<$inner_type<'a>>) -> Self {
                let total_size = vector
                    .iter()
                    .map(|e| e.len())
                    .fold(0u64, |sum, e| sum + e as u64);

                $type { vector, total_size }
            }
        }

        impl<'a> From<$buffer_type<'a>> for $type<'a> {
            fn from(buffer: $buffer_type<'a>) -> Self {
                let total_size = buffer.len() as u64;
                if total_size > 0 {
                    $type {
                        vector: vec![buffer.into()],
                        total_size,
                    }
                } else {
                    $type {
                        vector: Vec::new(),
                        total_size: 0,
                    }
                }
            }
        }

        impl<'a> From<$slice_type> for $type<'a> {
            fn from(slice: $slice_type) -> Self {
                let total_size = slice.len() as u64;
                if total_size > 0 {
                    $type {
                        vector: vec![$inner_type::new(slice)],
                        total_size,
                    }
                } else {
                    $type {
                        vector: Vec::new(),
                        total_size: 0,
                    }
                }
            }
        }

        impl<'a> Default for $type<'a> {
            fn default() -> Self {
                $type {
                    vector: Vec::new(),
                    total_size: 0,
                }
            }
        }

        impl Debug for $type<'_> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.debug_struct(std::stringify!($type))
                    .field("vector.len()", &self.vector.len())
                    .field("total_size", &self.total_size)
                    .finish()
            }
        }
    };
}

impl_io_vector!(IoVector, IoSlice, IoBufferRef, &'a [u8], &'b [u8]);
impl_io_vector!(
    IoVectorMut,
    IoSliceMut,
    IoBufferMut,
    &'a mut [u8],
    &'b mut [u8]
);

#[cfg(feature = "vm-memory")]
impl<'a> IoVector<'a> {
    /// Converts a `VolatileSlice` array (from vm-memory) into an `IoVector`.
    ///
    /// In addition to a the vector, return a guard that ensures that the memory in `slices` is
    /// indeed mapped while in use.  This guard must not be dropped while this vector is in use!
    pub fn from_volatile_slice<
        B: vm_memory::bitmap::BitmapSlice,
        I: IntoIterator<
            Item: ImagoAsRef<'a, vm_memory::VolatileSlice<'a, B>>,
            IntoIter: ExactSizeIterator,
        >,
    >(
        slices: I,
    ) -> (
        Self,
        VolatileSliceGuard<'a, vm_memory::volatile_memory::PtrGuard, B>,
    ) {
        let ptr_guards = slices
            .into_iter()
            .map(|slice| slice.as_ref().ptr_guard())
            .collect::<Vec<_>>();
        let buffers = ptr_guards
            .iter()
            .map(|pg| {
                // Safe because this whole module basically exists to follow the same design concepts
                // as `VolatileSlice`.
                let slice = unsafe { std::slice::from_raw_parts(pg.as_ptr(), pg.len()) };
                IoSlice::new(slice)
            })
            .collect::<Vec<_>>();

        let vector = IoVector::from(buffers);
        let guard = VolatileSliceGuard {
            _ptr_guards: ptr_guards,
            // `IoVector` is immutable, so no need to dirty
            dirty_on_drop: None,
        };

        (vector, guard)
    }
}

impl IoVectorMut<'_> {
    /// Fill all buffers in the vector with the given byte pattern.
    pub fn fill(&mut self, value: u8) {
        for slice in self.vector.iter_mut() {
            slice.fill(value);
        }
    }

    /// Copy data from `slice` into the buffers in this vector.
    ///
    /// The vector and the slice must have the same total length.
    pub fn copy_from_slice(&mut self, slice: &[u8]) {
        if slice.len() as u64 != self.total_size {
            panic!("IoVectorMut::copy_from_slice() called on a slice of different length from the vector");
        }

        assert!(self.total_size <= usize::MAX as u64);

        let mut offset = 0usize;
        for elem in self.vector.iter_mut() {
            let next_offset = offset + elem.len();
            elem.copy_from_slice(&slice[offset..next_offset]);
            offset = next_offset;
        }
    }
}

#[cfg(feature = "vm-memory")]
impl<'a> IoVectorMut<'a> {
    /// Converts a `VolatileSlice` array (from vm-memory) into an `IoVectorMut`.
    ///
    /// In addition to a the vector, return a guard that ensures that the memory in `slices` is
    /// indeed mapped while in use.  This guard must not be dropped while this vector is in use!
    pub fn from_volatile_slice<
        B: vm_memory::bitmap::BitmapSlice,
        I: IntoIterator<
            Item: ImagoAsRef<'a, vm_memory::VolatileSlice<'a, B>>,
            IntoIter: ExactSizeIterator,
        >,
    >(
        slices: I,
    ) -> (
        Self,
        VolatileSliceGuard<'a, vm_memory::volatile_memory::PtrGuardMut, B>,
    ) {
        let slices = slices.into_iter();
        let slice_count = slices.len();
        let mut ptr_guards = Vec::with_capacity(slice_count);
        let mut dirty_on_drop = Vec::with_capacity(slice_count);

        for slice in slices {
            let slice = slice.as_ref();
            ptr_guards.push(slice.ptr_guard_mut());
            // `IoVector` is mutable, so we can assume it will all be written
            dirty_on_drop.push((slice.bitmap(), slice.len()));
        }

        let buffers = ptr_guards
            .iter()
            .map(|pg| {
                // Safe because this whole module basically exists to follow the same design concepts
                // as `VolatileSlice`.
                let slice = unsafe { std::slice::from_raw_parts_mut(pg.as_ptr(), pg.len()) };
                IoSliceMut::new(slice)
            })
            .collect::<Vec<_>>();

        let vector = IoVectorMut::from(buffers);
        let guard = VolatileSliceGuard {
            _ptr_guards: ptr_guards,
            dirty_on_drop: Some(dirty_on_drop),
        };

        (vector, guard)
    }
}

impl<'a> From<&'a Vec<u8>> for IoVector<'a> {
    fn from(vec: &'a Vec<u8>) -> Self {
        vec.as_slice().into()
    }
}

impl<'a> From<&'a IoBuffer> for IoVector<'a> {
    fn from(buf: &'a IoBuffer) -> Self {
        buf.as_ref().into_slice().into()
    }
}

impl<'a> From<&'a mut Vec<u8>> for IoVectorMut<'a> {
    fn from(vec: &'a mut Vec<u8>) -> Self {
        vec.as_mut_slice().into()
    }
}

impl<'a> From<&'a mut IoBuffer> for IoVectorMut<'a> {
    fn from(buf: &'a mut IoBuffer) -> Self {
        buf.as_mut().into_slice().into()
    }
}

/// Ensures an I/O vector’s validity when created from `[VolatileSlice]`.
///
/// `[VolatileSlice]` arrays may require being explicitly mapped before use (and unmapped after),
/// and this guard ensures that the memory is mapped until it is dropped.
///
/// Further, for mutable vectors ([`IoVectorMut`]), it will also dirty the corresponding bitmap
/// slices when dropped, assuming the whole vector has been written.
#[cfg(feature = "vm-memory")]
pub struct VolatileSliceGuard<'a, PtrGuardType, BitmapType: vm_memory::bitmap::Bitmap> {
    /// vm-memory’s pointer guards ensuring the memory remains mapped while used.
    _ptr_guards: Vec<PtrGuardType>,

    /// If given, mark the given dirty bitmap range as dirty when dropping this guard.
    ///
    /// `.1` is the length of the respective `VolatileSlice` (i.e. the length of the area to
    /// dirty).
    dirty_on_drop: Option<Vec<(&'a BitmapType, usize)>>,
}

#[cfg(feature = "vm-memory")]
impl<P, B: vm_memory::bitmap::Bitmap> Drop for VolatileSliceGuard<'_, P, B> {
    fn drop(&mut self) {
        if let Some(dirty_on_drop) = self.dirty_on_drop.take() {
            for (bitmap, len) in dirty_on_drop {
                // Every bitmap is a window into the full bitmap for its specific `VolatileSlice`,
                // so marking the whole thing is dirty is correct.
                bitmap.mark_dirty(0, len);
            }
        }
    }
}

#[cfg(all(test, feature = "vm-memory"))]
mod vm_memory_test {
    use crate::io_buffers::{IoVector, IoVectorMut};
    use vm_memory::bitmap::BitmapSlice;
    use vm_memory::VolatileSlice;

    pub fn do_test_volatile_slice_owned<B: BitmapSlice>(slices: &[VolatileSlice<B>]) {
        {
            let _vec = IoVector::from_volatile_slice(slices);
        }
        {
            let _vec = IoVectorMut::from_volatile_slice(slices);
        }
    }

    #[test]
    fn test_volatile_slice_owned() {
        let empty: Vec<VolatileSlice<()>> = Vec::new();
        do_test_volatile_slice_owned(&empty);
    }

    pub fn do_test_volatile_slice_ref<B: BitmapSlice>(slices: &[&VolatileSlice<B>]) {
        {
            let _vec = IoVector::from_volatile_slice(slices);
        }
        {
            let _vec = IoVectorMut::from_volatile_slice(slices);
        }
    }

    #[test]
    fn test_volatile_slice_ref() {
        let empty: Vec<&vm_memory::VolatileSlice<()>> = Vec::new();
        do_test_volatile_slice_ref(&empty);
    }
}

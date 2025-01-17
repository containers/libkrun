//! Miscellaneous helper functions.

use std::io;
use std::ops::Range;

/// Checks whether something overlaps with something else.
pub(crate) trait Overlaps {
    /// Does this overlap with `other`?
    fn overlaps(&self, other: &Self) -> bool;
}

impl<I: Ord> Overlaps for Range<I> {
    fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Prepend `Error` messages by context.
///
/// Trait for `Error` objects that allows prepending their error messages by something that gives
/// context.
pub(crate) trait ErrorContext {
    /// Prepend the error by `context`.
    fn context<C: std::fmt::Display>(self, context: C) -> Self;
}

impl ErrorContext for io::Error {
    fn context<C: std::fmt::Display>(self, context: C) -> Self {
        io::Error::new(self.kind(), format!("{context}: {self}"))
    }
}

/// Give results context in case of error.
///
/// Lifts the `ErrorContext` trait to `Result` types.
pub(crate) trait ResultErrorContext {
    /// Give context if `self` is an error.
    ///
    /// If `self` is an error, prepend the given `context`.
    fn err_context<C: std::fmt::Display, F: FnOnce() -> C>(self, context: F) -> Self;
}

impl<V, E: ErrorContext> ResultErrorContext for Result<V, E> {
    fn err_context<C: std::fmt::Display, F: FnOnce() -> C>(self, context: F) -> Self {
        self.map_err(|err| err.context(context()))
    }
}

/// Similar to `AsRef`, but for types where `AsRef` is not implemented.
///
/// When we need `AsRef` for a type but it is not implemented in its origin crate, there is no way
/// but to provide a local trait that we can implement here.  Because there are no negative trait
/// bounds, we cannot implement this for `AsRef` (to have a common trait).
///
/// Also includes a lifetime so that it is possible to borrow things for longer.
pub trait ImagoAsRef<'a, T: ?Sized> {
    /// Return a simple reference for `self`.
    fn as_ref(&self) -> &'a T;
}

impl<'a, T: ?Sized, U: ImagoAsRef<'a, T>> ImagoAsRef<'a, T> for &'a U {
    fn as_ref(&self) -> &'a T {
        <U as ImagoAsRef<T>>::as_ref(self)
    }
}

#[cfg(feature = "vm-memory")]
impl<'a, B: vm_memory::bitmap::BitmapSlice> ImagoAsRef<'a, vm_memory::VolatileSlice<'a, B>>
    for &'a vm_memory::VolatileSlice<'a, B>
{
    fn as_ref(&self) -> &'a vm_memory::VolatileSlice<'a, B> {
        self
    }
}

/// Generate an `io::Error` of kind `InvalidData`.
pub(crate) fn invalid_data<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
    error: E,
) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

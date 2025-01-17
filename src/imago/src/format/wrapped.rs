//! Allows using [`FormatAccess`] in containers.
//!
//! Users may want to wrap [`FormatAccess`] objects e.g. in `Arc` and then assign them as
//! dependencies to other objects (e.g. as a backing image).  The [`WrappedFormat`] trait provided
//! here allows images to use other images (`FormatAccess` objects) regardless of whether they are
//! wrapped in such containers or not.

use crate::{FormatAccess, Storage};
use std::fmt::{Debug, Display};
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

/// Represents [`FormatAccess`] wrapped in e.g. `Arc`, `Box`, or nothing at all.
///
/// This struct is necessary so that we can reference format instances regardless of whether the
/// user decides to wrap them or not.
pub trait WrappedFormat<S: Storage>: Debug + Display + Send + Sync {
    /// Construct this `WrappedFormat`.
    fn wrap(inner: FormatAccess<S>) -> Self;

    /// Access the inner format instance.
    fn unwrap(&self) -> &FormatAccess<S>;
}

impl<
        S: Storage,
        D: Deref<Target = FormatAccess<S>> + Debug + Display + From<FormatAccess<S>> + Send + Sync,
    > WrappedFormat<S> for D
{
    fn wrap(inner: FormatAccess<S>) -> Self {
        Self::from(inner)
    }

    fn unwrap(&self) -> &FormatAccess<S> {
        self.deref()
    }
}

impl<S: Storage> WrappedFormat<S> for FormatAccess<S> {
    fn wrap(inner: FormatAccess<S>) -> Self {
        inner
    }

    fn unwrap(&self) -> &FormatAccess<S> {
        self
    }
}

impl<S: Storage> WrappedFormat<S> for OwnedRwLockReadGuard<FormatAccess<S>> {
    fn wrap(inner: FormatAccess<S>) -> Self {
        // Ugly, but works.
        Arc::new(RwLock::new(inner)).try_read_owned().unwrap()
    }

    fn unwrap(&self) -> &FormatAccess<S> {
        self.deref()
    }
}

//! Core functionality.
//!
//! Provides access to different image formats via `FormatAccess` objects.

pub mod access;
pub mod drivers;
#[cfg(feature = "sync-wrappers")]
pub mod sync_wrappers;
pub mod wrapped;

// Copyright 2026, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Common display utilities for device implementations.
//!
//! This module provides display-related functionality that can be shared
//! across different device types (virtio-gpu, vhost-user-gpu, etc.).

pub mod edid;
pub mod types;

#[cfg(feature = "gpu")]
pub mod display_backend;

pub use edid::EdidInfo;
pub use types::{EdidParams, PhysicalSize};

#[cfg(feature = "gpu")]
pub use display_backend::{DisplayInfo, DisplayInfoEdid, MAX_DISPLAYS, NoopDisplayBackend};

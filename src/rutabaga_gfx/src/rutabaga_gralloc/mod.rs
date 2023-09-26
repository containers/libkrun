// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements cross-platform allocation of window system buffers.
//! In addition, it may perform mappings of GPU buffers.  This is based on
//! "gralloc", a well-known Android hardware abstaction layer (HAL).
//!
//! <https://source.android.com/devices/graphics/arch-bq-gralloc>

mod formats;
mod gralloc;
mod minigbm;
mod minigbm_bindings;
mod rendernode;
mod system_gralloc;
mod vulkano_gralloc;

pub use formats::DrmFormat;
pub use gralloc::ImageAllocationInfo;
pub use gralloc::ImageMemoryRequirements;
pub use gralloc::RutabagaGralloc;
pub use gralloc::RutabagaGrallocFlags;

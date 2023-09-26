// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! gralloc: Cross-platform, Rust-based, Vulkan centric GPU allocation and
//! mapping.

use std::collections::BTreeMap as Map;

#[cfg(feature = "vulkano")]
use log::error;

use crate::rutabaga_gralloc::formats::*;
#[cfg(feature = "minigbm")]
use crate::rutabaga_gralloc::minigbm::MinigbmDevice;
use crate::rutabaga_gralloc::system_gralloc::SystemGralloc;
#[cfg(feature = "vulkano")]
use crate::rutabaga_gralloc::vulkano_gralloc::VulkanoGralloc;
use crate::rutabaga_os::round_up_to_page_size;
use crate::rutabaga_os::MappedRegion;
use crate::rutabaga_utils::*;

/*
 * Rutabaga gralloc flags are copied from minigbm, but redundant legacy flags are left out.
 * For example, USE_WRITE / USE_CURSOR_64X64 / USE_CURSOR don't add much value.
 */
const RUTABAGA_GRALLOC_USE_SCANOUT: u32 = 1 << 0;
const RUTABAGA_GRALLOC_USE_RENDERING: u32 = 1 << 2;
const RUTABAGA_GRALLOC_USE_LINEAR: u32 = 1 << 4;
const RUTABAGA_GRALLOC_USE_TEXTURING: u32 = 1 << 5;
const RUTABAGA_GRALLOC_USE_CAMERA_WRITE: u32 = 1 << 6;
const RUTABAGA_GRALLOC_USE_CAMERA_READ: u32 = 1 << 7;
#[allow(dead_code)]
const RUTABAGA_GRALLOC_USE_PROTECTED: u32 = 1 << 8;

/* SW_{WRITE,READ}_RARELY omitted since not even Android uses this much. */
const RUTABAGA_GRALLOC_USE_SW_READ_OFTEN: u32 = 1 << 9;
const RUTABAGA_GRALLOC_USE_SW_WRITE_OFTEN: u32 = 1 << 11;

#[allow(dead_code)]
const RUTABAGA_GRALLOC_VIDEO_DECODER: u32 = 1 << 13;
#[allow(dead_code)]
const RUTABAGA_GRALLOC_VIDEO_ENCODER: u32 = 1 << 14;

/// Usage flags for constructing a buffer object.
#[derive(Copy, Clone, Eq, PartialEq, Default)]
pub struct RutabagaGrallocFlags(pub u32);

impl RutabagaGrallocFlags {
    /// Returns empty set of flags.
    #[inline(always)]
    pub fn empty() -> RutabagaGrallocFlags {
        RutabagaGrallocFlags(0)
    }

    /// Returns the given set of raw `RUTABAGA_GRALLOC` flags wrapped in a RutabagaGrallocFlags
    /// struct.
    #[inline(always)]
    pub fn new(raw: u32) -> RutabagaGrallocFlags {
        RutabagaGrallocFlags(raw)
    }

    /// Sets the scanout flag's presence.
    #[inline(always)]
    pub fn use_scanout(self, e: bool) -> RutabagaGrallocFlags {
        if e {
            RutabagaGrallocFlags(self.0 | RUTABAGA_GRALLOC_USE_SCANOUT)
        } else {
            RutabagaGrallocFlags(self.0 & !RUTABAGA_GRALLOC_USE_SCANOUT)
        }
    }

    /// Sets the rendering flag's presence.
    #[inline(always)]
    pub fn use_rendering(self, e: bool) -> RutabagaGrallocFlags {
        if e {
            RutabagaGrallocFlags(self.0 | RUTABAGA_GRALLOC_USE_RENDERING)
        } else {
            RutabagaGrallocFlags(self.0 & !RUTABAGA_GRALLOC_USE_RENDERING)
        }
    }

    /// Sets the linear flag's presence.
    #[inline(always)]
    pub fn use_linear(self, e: bool) -> RutabagaGrallocFlags {
        if e {
            RutabagaGrallocFlags(self.0 | RUTABAGA_GRALLOC_USE_LINEAR)
        } else {
            RutabagaGrallocFlags(self.0 & !RUTABAGA_GRALLOC_USE_LINEAR)
        }
    }

    /// Sets the SW write flag's presence.
    #[inline(always)]
    pub fn use_sw_write(self, e: bool) -> RutabagaGrallocFlags {
        if e {
            RutabagaGrallocFlags(self.0 | RUTABAGA_GRALLOC_USE_SW_WRITE_OFTEN)
        } else {
            RutabagaGrallocFlags(self.0 & !RUTABAGA_GRALLOC_USE_SW_WRITE_OFTEN)
        }
    }

    /// Sets the SW read flag's presence.
    #[inline(always)]
    pub fn use_sw_read(self, e: bool) -> RutabagaGrallocFlags {
        if e {
            RutabagaGrallocFlags(self.0 | RUTABAGA_GRALLOC_USE_SW_READ_OFTEN)
        } else {
            RutabagaGrallocFlags(self.0 & !RUTABAGA_GRALLOC_USE_SW_READ_OFTEN)
        }
    }

    /// Returns true if the texturing flag is set.
    #[inline(always)]
    pub fn uses_texturing(self) -> bool {
        self.0 & RUTABAGA_GRALLOC_USE_TEXTURING != 0
    }

    /// Returns true if the rendering flag is set.
    #[inline(always)]
    pub fn uses_rendering(self) -> bool {
        self.0 & RUTABAGA_GRALLOC_USE_RENDERING != 0
    }

    /// Returns true if the memory will accessed by the CPU or an IP block that prefers host
    /// visible allocations (i.e, camera).
    #[inline(always)]
    pub fn host_visible(self) -> bool {
        self.0 & RUTABAGA_GRALLOC_USE_SW_READ_OFTEN != 0
            || self.0 & RUTABAGA_GRALLOC_USE_SW_WRITE_OFTEN != 0
            || self.0 & RUTABAGA_GRALLOC_USE_CAMERA_WRITE != 0
            || self.0 & RUTABAGA_GRALLOC_USE_CAMERA_READ != 0
    }

    /// Returns true if the memory will read by the CPU or an IP block that prefers cached
    /// allocations (i.e, camera).
    #[inline(always)]
    pub fn host_cached(self) -> bool {
        self.0 & RUTABAGA_GRALLOC_USE_CAMERA_READ != 0
            || self.0 & RUTABAGA_GRALLOC_USE_SW_READ_OFTEN != 0
    }
}

/// Information required to allocate a swapchain image.
#[derive(Copy, Clone, Default)]
pub struct ImageAllocationInfo {
    pub width: u32,
    pub height: u32,
    pub drm_format: DrmFormat,
    pub flags: RutabagaGrallocFlags,
}

/// The memory requirements, compression and layout of a swapchain image.
#[derive(Copy, Clone, Default)]
pub struct ImageMemoryRequirements {
    pub info: ImageAllocationInfo,
    pub map_info: u32,
    pub strides: [u32; 4],
    pub offsets: [u32; 4],
    pub modifier: u64,
    pub size: u64,
    pub vulkan_info: Option<VulkanInfo>,
}

/// Trait that needs to be implemented to service graphics memory requests.  Two step allocation
/// process:
///
///   (1) Get memory requirements for a given allocation request.
///   (2) Allocate using those requirements.
pub trait Gralloc: Send {
    /// This function must return true if the implementation can:
    ///
    ///   (1) allocate GPU memory and
    ///   (2) {export to}/{import from} into a OS-specific RutabagaHandle.
    fn supports_external_gpu_memory(&self) -> bool;

    /// This function must return true the implementation can {export to}/{import from} a Linux
    /// dma-buf.  This often used for sharing with the scanout engine or multimedia subsystems.
    fn supports_dmabuf(&self) -> bool;

    /// Implementations must return the resource layout, compression, and caching properties of
    /// an allocation request.
    fn get_image_memory_requirements(
        &mut self,
        info: ImageAllocationInfo,
    ) -> RutabagaResult<ImageMemoryRequirements>;

    /// Implementations must allocate memory given the requirements and return a RutabagaHandle
    /// upon success.
    fn allocate_memory(&mut self, reqs: ImageMemoryRequirements) -> RutabagaResult<RutabagaHandle>;

    /// Implementations must import the given `handle` and return a mapping, suitable for use with
    /// KVM and other hypervisors.  This is optional and only works with the Vulkano backend.
    fn import_and_map(
        &mut self,
        _handle: RutabagaHandle,
        _vulkan_info: VulkanInfo,
        _size: u64,
    ) -> RutabagaResult<Box<dyn MappedRegion>> {
        Err(RutabagaError::Unsupported)
    }
}

/// Enumeration of possible allocation backends.
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum GrallocBackend {
    #[allow(dead_code)]
    Vulkano,
    #[allow(dead_code)]
    Minigbm,
    System,
}

/// A container for a variety of allocation backends.
pub struct RutabagaGralloc {
    grallocs: Map<GrallocBackend, Box<dyn Gralloc>>,
}

impl RutabagaGralloc {
    /// Returns a new RutabagaGralloc instance upon success.  All allocation backends that have
    /// been built are initialized.  The default system allocator is always initialized.
    pub fn new() -> RutabagaResult<RutabagaGralloc> {
        let mut grallocs: Map<GrallocBackend, Box<dyn Gralloc>> = Default::default();

        let system = SystemGralloc::init()?;
        grallocs.insert(GrallocBackend::System, system);

        #[cfg(feature = "minigbm")]
        {
            // crosvm integration tests build with the "wl-dmabuf" feature, which translates in
            // rutabaga to the "minigbm" feature.  These tests run on hosts where a rendernode is
            // not present, and minigbm can not be initialized.
            //
            // Thus, to keep kokoro happy, allow minigbm initialization to fail silently for now.
            if let Ok(gbm_device) = MinigbmDevice::init() {
                grallocs.insert(GrallocBackend::Minigbm, gbm_device);
            }
        }

        #[cfg(feature = "vulkano")]
        {
            match VulkanoGralloc::init() {
                Ok(vulkano) => {
                    grallocs.insert(GrallocBackend::Vulkano, vulkano);
                }
                Err(e) => {
                    error!("failed to init Vulkano gralloc: {:?}", e);
                }
            }
        }

        Ok(RutabagaGralloc { grallocs })
    }

    /// Returns true if one of the allocation backends supports GPU external memory.
    pub fn supports_external_gpu_memory(&self) -> bool {
        for gralloc in self.grallocs.values() {
            if gralloc.supports_external_gpu_memory() {
                return true;
            }
        }

        false
    }

    /// Returns true if one of the allocation backends supports dma_buf.
    pub fn supports_dmabuf(&self) -> bool {
        for gralloc in self.grallocs.values() {
            if gralloc.supports_dmabuf() {
                return true;
            }
        }

        false
    }

    /// Returns the best allocation backend to service a particular request.
    fn determine_optimal_backend(&self, _info: ImageAllocationInfo) -> GrallocBackend {
        // This function could be more sophisticated and consider the allocation info.  For example,
        // nobody has ever tried Mali allocated memory + a mediatek/rockchip display and as such it
        // probably doesn't work.  In addition, YUV calculations in minigbm have yet to make it
        // towards the Vulkan api.  This function allows for a variety of quirks, but for now just
        // choose the most shiny backend that the user has built.  The rationale is "why would you
        // build it if you don't want to use it".
        #[allow(clippy::let_and_return)]
        let mut _backend = GrallocBackend::System;

        #[cfg(feature = "minigbm")]
        {
            // See note on "wl-dmabuf" and Kokoro in Gralloc::new().
            if self.grallocs.contains_key(&GrallocBackend::Minigbm) {
                _backend = GrallocBackend::Minigbm;
            }
        }

        #[cfg(feature = "vulkano")]
        {
            _backend = GrallocBackend::Vulkano;
        }

        _backend
    }

    /// Returns a image memory requirements for the given `info` upon success.
    pub fn get_image_memory_requirements(
        &mut self,
        info: ImageAllocationInfo,
    ) -> RutabagaResult<ImageMemoryRequirements> {
        let backend = self.determine_optimal_backend(info);

        let gralloc = self
            .grallocs
            .get_mut(&backend)
            .ok_or(RutabagaError::InvalidGrallocBackend)?;

        let mut reqs = gralloc.get_image_memory_requirements(info)?;
        reqs.size = round_up_to_page_size(reqs.size)?;
        Ok(reqs)
    }

    /// Allocates memory given the particular `reqs` upon success.
    pub fn allocate_memory(
        &mut self,
        reqs: ImageMemoryRequirements,
    ) -> RutabagaResult<RutabagaHandle> {
        let backend = self.determine_optimal_backend(reqs.info);

        let gralloc = self
            .grallocs
            .get_mut(&backend)
            .ok_or(RutabagaError::InvalidGrallocBackend)?;

        gralloc.allocate_memory(reqs)
    }

    /// Imports the `handle` using the given `vulkan_info`.  Returns a mapping using Vulkano upon
    /// success.  Should not be used with minigbm or system gralloc backends.
    pub fn import_and_map(
        &mut self,
        handle: RutabagaHandle,
        vulkan_info: VulkanInfo,
        size: u64,
    ) -> RutabagaResult<Box<dyn MappedRegion>> {
        let gralloc = self
            .grallocs
            .get_mut(&GrallocBackend::Vulkano)
            .ok_or(RutabagaError::InvalidGrallocBackend)?;

        gralloc.import_and_map(handle, vulkan_info, size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(target_os = "windows", ignore)]
    fn create_render_target() {
        let gralloc_result = RutabagaGralloc::new();
        if gralloc_result.is_err() {
            return;
        }

        let mut gralloc = gralloc_result.unwrap();

        let info = ImageAllocationInfo {
            width: 512,
            height: 1024,
            drm_format: DrmFormat::new(b'X', b'R', b'2', b'4'),
            flags: RutabagaGrallocFlags::empty().use_scanout(true),
        };

        let reqs = gralloc.get_image_memory_requirements(info).unwrap();
        let min_reqs = canonical_image_requirements(info).unwrap();

        assert!(reqs.strides[0] >= min_reqs.strides[0]);
        assert!(reqs.size >= min_reqs.size);

        let _handle = gralloc.allocate_memory(reqs).unwrap();

        // Reallocate with same requirements
        let _handle2 = gralloc.allocate_memory(reqs).unwrap();
    }

    #[test]
    #[cfg_attr(target_os = "windows", ignore)]
    fn create_video_buffer() {
        let gralloc_result = RutabagaGralloc::new();
        if gralloc_result.is_err() {
            return;
        }

        let mut gralloc = gralloc_result.unwrap();

        let info = ImageAllocationInfo {
            width: 512,
            height: 1024,
            drm_format: DrmFormat::new(b'N', b'V', b'1', b'2'),
            flags: RutabagaGrallocFlags::empty().use_linear(true),
        };

        let reqs = gralloc.get_image_memory_requirements(info).unwrap();
        let min_reqs = canonical_image_requirements(info).unwrap();

        assert!(reqs.strides[0] >= min_reqs.strides[0]);
        assert!(reqs.strides[1] >= min_reqs.strides[1]);
        assert_eq!(reqs.strides[2], 0);
        assert_eq!(reqs.strides[3], 0);

        assert!(reqs.offsets[0] >= min_reqs.offsets[0]);
        assert!(reqs.offsets[1] >= min_reqs.offsets[1]);
        assert_eq!(reqs.offsets[2], 0);
        assert_eq!(reqs.offsets[3], 0);

        assert!(reqs.size >= min_reqs.size);

        let _handle = gralloc.allocate_memory(reqs).unwrap();

        // Reallocate with same requirements
        let _handle2 = gralloc.allocate_memory(reqs).unwrap();
    }

    #[test]
    #[cfg_attr(target_os = "windows", ignore)]
    fn export_and_map() {
        let gralloc_result = RutabagaGralloc::new();
        if gralloc_result.is_err() {
            return;
        }

        let mut gralloc = gralloc_result.unwrap();

        let info = ImageAllocationInfo {
            width: 512,
            height: 1024,
            drm_format: DrmFormat::new(b'X', b'R', b'2', b'4'),
            flags: RutabagaGrallocFlags::empty()
                .use_linear(true)
                .use_sw_write(true)
                .use_sw_read(true),
        };

        let mut reqs = gralloc.get_image_memory_requirements(info).unwrap();

        // Anything else can use the mmap(..) system call.
        if reqs.vulkan_info.is_none() {
            return;
        }

        let handle = gralloc.allocate_memory(reqs).unwrap();
        let vulkan_info = reqs.vulkan_info.take().unwrap();

        let mapping = gralloc
            .import_and_map(handle, vulkan_info, reqs.size)
            .unwrap();

        let addr = mapping.as_ptr();
        let size = mapping.size();

        assert_eq!(size as u64, reqs.size);
        assert_ne!(addr as *const u8, std::ptr::null());
    }
}

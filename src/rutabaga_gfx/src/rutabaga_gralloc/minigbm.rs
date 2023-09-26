// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! minigbm: implements swapchain allocation using ChromeOS's minigbm library.
//!
//! External code found at <https://chromium.googlesource.com/chromiumos/platform/minigbm>.

#![cfg(feature = "minigbm")]

use std::ffi::CStr;
use std::fs::File;
use std::io::Error;
use std::io::Seek;
use std::io::SeekFrom;
use std::os::raw::c_char;
use std::sync::Arc;

use crate::rutabaga_gralloc::formats::DrmFormat;
use crate::rutabaga_gralloc::gralloc::Gralloc;
use crate::rutabaga_gralloc::gralloc::ImageAllocationInfo;
use crate::rutabaga_gralloc::gralloc::ImageMemoryRequirements;
use crate::rutabaga_gralloc::minigbm_bindings::*;
use crate::rutabaga_gralloc::rendernode;
use crate::rutabaga_os::AsRawDescriptor;
use crate::rutabaga_os::FromRawDescriptor;
use crate::rutabaga_utils::*;

struct MinigbmDeviceInner {
    _fd: File,
    gbm: *mut gbm_device,
}

// Safe because minigbm handles synchronization internally.
unsafe impl Send for MinigbmDeviceInner {}
unsafe impl Sync for MinigbmDeviceInner {}

impl Drop for MinigbmDeviceInner {
    fn drop(&mut self) {
        // Safe because MinigbmDeviceInner is only constructed with a valid minigbm_device.
        unsafe {
            gbm_device_destroy(self.gbm);
        }
    }
}

/// A device capable of allocating `MinigbmBuffer`.
#[derive(Clone)]
pub struct MinigbmDevice {
    minigbm_device: Arc<MinigbmDeviceInner>,
    last_buffer: Option<Arc<MinigbmBuffer>>,
    device_name: &'static str,
}

impl MinigbmDevice {
    /// Returns a new `MinigbmDevice` if there is a rendernode in `/dev/dri/` that is accepted by
    /// the minigbm library.
    pub fn init() -> RutabagaResult<Box<dyn Gralloc>> {
        let undesired: &[&str] = &["vgem", "pvr"];
        let fd = rendernode::open_device(undesired)?;

        // gbm_create_device is safe to call with a valid fd, and we check that a valid one is
        // returned.  If the fd does not refer to a DRM device, gbm_create_device will reject it.
        let gbm = unsafe { gbm_create_device(fd.as_raw_descriptor()) };
        if gbm.is_null() {
            return Err(RutabagaError::IoError(Error::last_os_error()));
        }

        // Safe because a valid minigbm device has a statically allocated string associated with
        // it, which is valid for the lifetime of the process.
        let backend_name: *const c_char = unsafe { gbm_device_get_backend_name(gbm) };
        let c_str: &CStr = unsafe { CStr::from_ptr(backend_name) };
        let device_name: &str = c_str.to_str()?;

        Ok(Box::new(MinigbmDevice {
            minigbm_device: Arc::new(MinigbmDeviceInner { _fd: fd, gbm }),
            last_buffer: None,
            device_name,
        }))
    }
}

impl Gralloc for MinigbmDevice {
    fn supports_external_gpu_memory(&self) -> bool {
        true
    }

    fn supports_dmabuf(&self) -> bool {
        true
    }

    fn get_image_memory_requirements(
        &mut self,
        info: ImageAllocationInfo,
    ) -> RutabagaResult<ImageMemoryRequirements> {
        let bo = unsafe {
            gbm_bo_create(
                self.minigbm_device.gbm,
                info.width,
                info.height,
                info.drm_format.0,
                info.flags.0,
            )
        };
        if bo.is_null() {
            return Err(RutabagaError::IoError(Error::last_os_error()));
        }

        let mut reqs: ImageMemoryRequirements = Default::default();
        let gbm_buffer = MinigbmBuffer(bo, self.clone());

        // Intel GPUs typically only use cached memory buffers.  This will change with dGPUs, but
        // perhaps minigbm will be deprecated by then.  Other display drivers (rockchip, mediatek,
        // amdgpu) typically use write combine memory.  We can also consider use flags too if this
        // heuristic proves insufficient.
        if self.device_name == "i915" {
            reqs.map_info = RUTABAGA_MAP_CACHE_CACHED;
        } else {
            reqs.map_info = RUTABAGA_MAP_CACHE_WC;
        }

        reqs.modifier = gbm_buffer.format_modifier();
        for plane in 0..gbm_buffer.num_planes() {
            reqs.strides[plane] = gbm_buffer.plane_stride(plane);
            reqs.offsets[plane] = gbm_buffer.plane_offset(plane);
        }

        let mut fd = gbm_buffer.export()?;
        let size = fd.seek(SeekFrom::End(0))?;

        // minigbm does have the ability to query image requirements without allocating memory
        // via the TEST_ALLOC flag.  However, support has only been added in i915.  Until this
        // flag is supported everywhere, do the actual allocation here and stash it away.
        if self.last_buffer.is_some() {
            return Err(RutabagaError::AlreadyInUse);
        }

        self.last_buffer = Some(Arc::new(gbm_buffer));
        reqs.info = info;
        reqs.size = size;
        Ok(reqs)
    }

    fn allocate_memory(&mut self, reqs: ImageMemoryRequirements) -> RutabagaResult<RutabagaHandle> {
        let last_buffer = self.last_buffer.take();
        if let Some(gbm_buffer) = last_buffer {
            if gbm_buffer.width() != reqs.info.width
                || gbm_buffer.height() != reqs.info.height
                || gbm_buffer.format() != reqs.info.drm_format
            {
                return Err(RutabagaError::InvalidGrallocDimensions);
            }

            let dmabuf = gbm_buffer.export()?.into();
            return Ok(RutabagaHandle {
                os_handle: dmabuf,
                handle_type: RUTABAGA_MEM_HANDLE_TYPE_DMABUF,
            });
        }

        let bo = unsafe {
            gbm_bo_create(
                self.minigbm_device.gbm,
                reqs.info.width,
                reqs.info.height,
                reqs.info.drm_format.0,
                reqs.info.flags.0,
            )
        };

        if bo.is_null() {
            return Err(RutabagaError::IoError(Error::last_os_error()));
        }

        let gbm_buffer = MinigbmBuffer(bo, self.clone());
        let dmabuf = gbm_buffer.export()?.into();
        Ok(RutabagaHandle {
            os_handle: dmabuf,
            handle_type: RUTABAGA_MEM_HANDLE_TYPE_DMABUF,
        })
    }
}

/// An allocation from a `MinigbmDevice`.
pub struct MinigbmBuffer(*mut gbm_bo, MinigbmDevice);

// Safe because minigbm handles synchronization internally.
unsafe impl Send for MinigbmBuffer {}
unsafe impl Sync for MinigbmBuffer {}

impl MinigbmBuffer {
    /// Width in pixels.
    pub fn width(&self) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_width(self.0) }
    }

    /// Height in pixels.
    pub fn height(&self) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_height(self.0) }
    }

    /// `DrmFormat` of the buffer.
    pub fn format(&self) -> DrmFormat {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { DrmFormat(gbm_bo_get_format(self.0)) }
    }

    /// DrmFormat modifier flags for the buffer.
    pub fn format_modifier(&self) -> u64 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_modifier(self.0) }
    }

    /// Number of planes present in this buffer.
    pub fn num_planes(&self) -> usize {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_plane_count(self.0) as usize }
    }

    /// Offset in bytes for the given plane.
    pub fn plane_offset(&self, plane: usize) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_offset(self.0, plane) }
    }

    /// Length in bytes of one row for the given plane.
    pub fn plane_stride(&self, plane: usize) -> u32 {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_get_stride_for_plane(self.0, plane) }
    }

    /// Exports a new dmabuf/prime file descriptor.
    pub fn export(&self) -> RutabagaResult<File> {
        // This is always safe to call with a valid gbm_bo pointer.
        match unsafe { gbm_bo_get_fd(self.0) } {
            fd if fd >= 0 => {
                let dmabuf = unsafe { File::from_raw_descriptor(fd) };
                Ok(dmabuf)
            }
            ret => Err(RutabagaError::ComponentError(ret)),
        }
    }
}

impl Drop for MinigbmBuffer {
    fn drop(&mut self) {
        // This is always safe to call with a valid gbm_bo pointer.
        unsafe { gbm_bo_destroy(self.0) }
    }
}

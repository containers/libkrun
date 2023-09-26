// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::sync::Arc;

use vulkano::device::Device;
use vulkano::device::DeviceExtensions;
use vulkano::memory::DeviceMemory;
use vulkano::memory::ExternalMemoryHandleType;
use vulkano::memory::MemoryAllocateInfo;
use vulkano::memory::MemoryImportInfo;

use crate::rutabaga_gralloc::vulkano_gralloc::VulkanoGralloc;
use crate::rutabaga_os::FromRawDescriptor;
use crate::rutabaga_os::IntoRawDescriptor;
use crate::rutabaga_utils::RUTABAGA_MEM_HANDLE_TYPE_DMABUF;
use crate::rutabaga_utils::RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD;
use crate::RutabagaError;
use crate::RutabagaHandle;
use crate::RutabagaResult;

impl VulkanoGralloc {
    /// Get the extensions that should be enabled.
    pub(crate) fn get_desired_device_extensions() -> DeviceExtensions {
        DeviceExtensions {
            khr_dedicated_allocation: true,
            khr_get_memory_requirements2: true,
            khr_external_memory: true,
            khr_external_memory_fd: true,
            ext_external_memory_dma_buf: true,
            ..DeviceExtensions::empty()
        }
    }

    /// Import memory from a handle.
    ///
    /// # Safety
    /// Safe if the memory handle given is an opaque FD or a DMA buffer handle, and the allocation
    /// info matches the information at the time the memory was created.
    pub(crate) unsafe fn import_memory(
        device: Arc<Device>,
        allocate_info: MemoryAllocateInfo,
        handle: RutabagaHandle,
    ) -> RutabagaResult<DeviceMemory> {
        let import_info = MemoryImportInfo::Fd {
            handle_type: match handle.handle_type {
                RUTABAGA_MEM_HANDLE_TYPE_DMABUF => ExternalMemoryHandleType::DmaBuf,
                RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD => ExternalMemoryHandleType::OpaqueFd,
                _ => return Err(RutabagaError::InvalidRutabagaHandle),
            },
            // Safe because we own the handle.
            file: File::from_raw_descriptor(handle.os_handle.into_raw_descriptor()),
        };

        Ok(DeviceMemory::import(device, allocate_info, import_info)?)
    }
}

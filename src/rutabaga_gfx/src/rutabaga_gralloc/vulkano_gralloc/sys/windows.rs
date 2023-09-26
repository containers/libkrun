// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use vulkano::device::Device;
use vulkano::device::DeviceExtensions;
use vulkano::memory::DeviceMemory;
use vulkano::memory::ExternalMemoryHandleType;
use vulkano::memory::MemoryAllocateInfo;
use vulkano::memory::MemoryImportInfo;

use crate::rutabaga_gralloc::vulkano_gralloc::VulkanoGralloc;
use crate::rutabaga_os::AsRawDescriptor;
use crate::rutabaga_utils::RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_WIN32;
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
            khr_external_memory_win32: true,
            ..DeviceExtensions::empty()
        }
    }

    /// Import memory from a handle.
    ///
    /// # Safety
    /// Safe if the memory handle given is an opaque Win32 handle, and the allocation info matches
    /// the information at the time the memory was created.
    pub(crate) unsafe fn import_memory(
        device: Arc<Device>,
        allocate_info: MemoryAllocateInfo,
        handle: RutabagaHandle,
    ) -> RutabagaResult<DeviceMemory> {
        let import_info = MemoryImportInfo::Win32 {
            handle_type: match handle.handle_type {
                RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_WIN32 => ExternalMemoryHandleType::OpaqueWin32,
                _ => return Err(RutabagaError::InvalidRutabagaHandle),
            },
            handle: handle.os_handle.as_raw_descriptor(),
        };

        Ok(DeviceMemory::import(device, allocate_info, import_info)?)
    }
}

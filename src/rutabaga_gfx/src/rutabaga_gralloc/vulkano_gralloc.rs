// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! vulkano_gralloc: Implements swapchain allocation and memory mapping
//! using Vulkano.
//!
//! External code found at https://github.com/vulkano-rs/vulkano.

#![cfg(feature = "vulkano")]

mod sys;

use std::collections::HashMap as Map;
use std::convert::TryInto;
use std::sync::Arc;

use log::warn;
use vulkano::device::physical::PhysicalDeviceType;
use vulkano::device::Device;
use vulkano::device::DeviceCreateInfo;
use vulkano::device::DeviceCreationError;
use vulkano::device::QueueCreateInfo;
use vulkano::image;
use vulkano::image::ImageCreationError;
use vulkano::image::ImageDimensions;
use vulkano::image::ImageUsage;
use vulkano::image::SampleCount;
use vulkano::instance::Instance;
use vulkano::instance::InstanceCreateInfo;
use vulkano::instance::InstanceCreationError;
use vulkano::instance::InstanceExtensions;
use vulkano::instance::Version;
use vulkano::memory::pool::AllocFromRequirementsFilter;
use vulkano::memory::DedicatedAllocation;
use vulkano::memory::DeviceMemory;
use vulkano::memory::DeviceMemoryError;
use vulkano::memory::ExternalMemoryHandleType;
use vulkano::memory::ExternalMemoryHandleTypes;
use vulkano::memory::MappedDeviceMemory;
use vulkano::memory::MemoryAllocateInfo;
use vulkano::memory::MemoryMapError;
use vulkano::memory::MemoryRequirements;
use vulkano::memory::MemoryType;
use vulkano::sync::Sharing;
use vulkano::LoadingError;
use vulkano::VulkanError;
use vulkano::VulkanLibrary;

use crate::rutabaga_gralloc::gralloc::Gralloc;
use crate::rutabaga_gralloc::gralloc::ImageAllocationInfo;
use crate::rutabaga_gralloc::gralloc::ImageMemoryRequirements;
use crate::rutabaga_os::MappedRegion;
use crate::rutabaga_utils::*;

/// A gralloc implementation capable of allocation `VkDeviceMemory`.
pub struct VulkanoGralloc {
    devices: Map<PhysicalDeviceType, Arc<Device>>,
    device_by_id: Map<DeviceId, Arc<Device>>,
    has_integrated_gpu: bool,
}

struct VulkanoMapping {
    mapped_memory: MappedDeviceMemory,
    size: usize,
}

impl VulkanoMapping {
    pub fn new(mapped_memory: MappedDeviceMemory, size: usize) -> VulkanoMapping {
        VulkanoMapping {
            mapped_memory,
            size,
        }
    }
}

unsafe impl MappedRegion for VulkanoMapping {
    /// Used for passing this region for hypervisor memory mappings.  We trust crosvm to use this
    /// safely.
    fn as_ptr(&self) -> *mut u8 {
        unsafe {
            // Will not panic since the requested range of the device memory was verified on
            // creation
            let x = self.mapped_memory.write(0..self.size as u64).unwrap();
            x.as_mut_ptr()
        }
    }

    /// Returns the size of the memory region in bytes.
    fn size(&self) -> usize {
        self.size
    }
}

trait DeviceExt {
    /// Get a unique identifier for the device.
    fn get_id(&self) -> DeviceId;
}

impl DeviceExt for Device {
    fn get_id(&self) -> DeviceId {
        let properties = self.physical_device().properties();
        DeviceId {
            device_uuid: properties.device_uuid.expect("Vulkan should support uuid"),
            driver_uuid: properties.driver_uuid.expect("Vulkan should support uuid"),
        }
    }
}

impl VulkanoGralloc {
    /// Returns a new `VulkanGralloc' instance upon success.
    pub fn init() -> RutabagaResult<Box<dyn Gralloc>> {
        // Initialization copied from triangle.rs in Vulkano.  Look there for a more detailed
        // explanation of VK initialization.
        let library = VulkanLibrary::new()?;

        let instance_extensions = InstanceExtensions {
            khr_external_memory_capabilities: true,
            khr_get_physical_device_properties2: true,
            ..InstanceExtensions::empty()
        };
        let instance = Instance::new(
            library,
            InstanceCreateInfo {
                enabled_extensions: instance_extensions,
                max_api_version: Some(Version::V1_1),
                ..Default::default()
            },
        )?;

        let mut devices: Map<PhysicalDeviceType, Arc<Device>> = Default::default();
        let mut device_by_id: Map<DeviceId, Arc<Device>> = Default::default();
        let mut has_integrated_gpu = false;

        for physical in instance.enumerate_physical_devices()? {
            let queue_family_index = match physical.queue_family_properties().iter().position(|q| {
                // We take the first queue family that supports graphics.
                q.queue_flags.graphics
            }) {
                Some(family) => family,
                None => {
                    warn!(
                        "Skipping Vulkano for {} due to no graphics queue",
                        physical.properties().device_name
                    );
                    continue;
                }
            };

            let supported_extensions = physical.supported_extensions();

            let desired_extensions = Self::get_desired_device_extensions();

            let intersection = supported_extensions.intersection(&desired_extensions);

            if let Ok((device, mut _queues)) = Device::new(
                physical.clone(),
                DeviceCreateInfo {
                    enabled_extensions: intersection,
                    queue_create_infos: vec![QueueCreateInfo {
                        queue_family_index: queue_family_index as u32,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ) {
                let device_type = device.physical_device().properties().device_type;
                if device_type == PhysicalDeviceType::IntegratedGpu {
                    has_integrated_gpu = true
                }

                // If we have two devices of the same type (two integrated GPUs), the old value is
                // dropped.  Vulkano is verbose enough such that a keener selection algorithm may
                // be used, but the need for such complexity does not seem to exist now.
                devices.insert(device_type, device.clone());
                device_by_id.insert(device.get_id(), device);
            };
        }

        if devices.is_empty() {
            return Err(RutabagaError::SpecViolation(
                "no matching VK devices available",
            ));
        }

        Ok(Box::new(VulkanoGralloc {
            devices,
            device_by_id,
            has_integrated_gpu,
        }))
    }

    // This function is used safely in this module because gralloc does not:
    //
    //  (1) bind images to any memory.
    //  (2) transition the layout of images.
    //  (3) transfer ownership of images between queues.
    //
    // In addition, we trust Vulkano to validate image parameters are within the Vulkan spec.
    // TODO(tutankhamen): Do we still need a separate MemoryRequirements?
    unsafe fn create_image(
        &mut self,
        info: ImageAllocationInfo,
    ) -> RutabagaResult<(Arc<image::sys::UnsafeImage>, MemoryRequirements)> {
        let device = if self.has_integrated_gpu {
            self.devices
                .get(&PhysicalDeviceType::IntegratedGpu)
                .ok_or(RutabagaError::InvalidGrallocGpuType)?
        } else {
            self.devices
                .get(&PhysicalDeviceType::DiscreteGpu)
                .ok_or(RutabagaError::InvalidGrallocGpuType)?
        };

        let usage = match info.flags.uses_rendering() {
            true => ImageUsage {
                color_attachment: true,
                ..ImageUsage::empty()
            },
            false => ImageUsage {
                sampled: true,
                ..ImageUsage::empty()
            },
        };

        // Reasonable bounds on image width.
        if info.width == 0 || info.width > 4096 {
            return Err(RutabagaError::InvalidGrallocDimensions);
        }

        // Reasonable bounds on image height.
        if info.height == 0 || info.height > 4096 {
            return Err(RutabagaError::InvalidGrallocDimensions);
        }

        let vulkan_format = info.drm_format.vulkan_format()?;
        let unsafe_image = image::sys::UnsafeImage::new(
            device.clone(),
            image::sys::UnsafeImageCreateInfo {
                dimensions: ImageDimensions::Dim2d {
                    width: info.width,
                    height: info.height,
                    array_layers: 1,
                },
                format: Some(vulkan_format),
                samples: SampleCount::Sample1,
                usage,
                mip_levels: 1,
                sharing: Sharing::Exclusive,
                ..Default::default()
            },
        )?;

        let memory_requirements = unsafe_image.memory_requirements();

        Ok((unsafe_image, memory_requirements))
    }
}

impl Gralloc for VulkanoGralloc {
    fn supports_external_gpu_memory(&self) -> bool {
        for device in self.devices.values() {
            if !device.enabled_extensions().khr_external_memory {
                return false;
            }
        }

        true
    }

    fn supports_dmabuf(&self) -> bool {
        for device in self.devices.values() {
            if !device.enabled_extensions().ext_external_memory_dma_buf {
                return false;
            }
        }

        true
    }

    fn get_image_memory_requirements(
        &mut self,
        info: ImageAllocationInfo,
    ) -> RutabagaResult<ImageMemoryRequirements> {
        let mut reqs: ImageMemoryRequirements = Default::default();

        let (unsafe_image, memory_requirements) = unsafe { self.create_image(info)? };

        let device_type = if self.has_integrated_gpu {
            &PhysicalDeviceType::IntegratedGpu
        } else {
            &PhysicalDeviceType::DiscreteGpu
        };

        let device = self
            .devices
            .get(device_type)
            .ok_or(RutabagaError::InvalidGrallocGpuType)?;

        let planar_layout = info.drm_format.planar_layout()?;

        // Safe because we created the image with the linear bit set and verified the format is
        // not a depth or stencil format.  We are also using the correct image aspect.  Vulkano
        // will panic if we are not.
        for plane in 0..planar_layout.num_planes {
            let aspect = info.drm_format.vulkan_image_aspect(plane)?;
            let layout = unsafe { unsafe_image.multiplane_color_layout(aspect) };
            reqs.strides[plane] = layout.row_pitch as u32;
            reqs.offsets[plane] = layout.offset as u32;
        }

        let need_visible = info.flags.host_visible();
        let want_cached = info.flags.host_cached();

        let (memory_type_index, memory_type) = {
            let filter = |current_type: &MemoryType| {
                if need_visible && !current_type.property_flags.host_visible {
                    return AllocFromRequirementsFilter::Forbidden;
                }

                if !need_visible && current_type.property_flags.device_local {
                    return AllocFromRequirementsFilter::Preferred;
                }

                if need_visible && want_cached && current_type.property_flags.host_cached {
                    return AllocFromRequirementsFilter::Preferred;
                }

                if need_visible
                    && !want_cached
                    && current_type.property_flags.host_coherent
                    && !current_type.property_flags.host_cached
                {
                    return AllocFromRequirementsFilter::Preferred;
                }

                AllocFromRequirementsFilter::Allowed
            };

            let first_loop = device
                .physical_device()
                .memory_properties()
                .memory_types
                .iter()
                .enumerate()
                .map(|(i, t)| (i, t, AllocFromRequirementsFilter::Preferred));
            let second_loop = device
                .physical_device()
                .memory_properties()
                .memory_types
                .iter()
                .enumerate()
                .map(|(i, t)| (i, t, AllocFromRequirementsFilter::Allowed));
            let found_type = first_loop
                .chain(second_loop)
                .filter(|&(i, _, _)| (memory_requirements.memory_type_bits & (1 << i)) != 0)
                .find(|&(_, t, rq)| filter(t) == rq)
                .ok_or(RutabagaError::SpecViolation(
                    "unable to find required memory type",
                ))?;
            (found_type.0, found_type.1)
        };

        reqs.info = info;
        reqs.size = memory_requirements.size as u64;

        if memory_type.property_flags.host_visible {
            if memory_type.property_flags.host_cached {
                reqs.map_info = RUTABAGA_MAP_CACHE_CACHED;
            } else if memory_type.property_flags.host_coherent {
                reqs.map_info = RUTABAGA_MAP_CACHE_WC;
            }
        }

        reqs.vulkan_info = Some(VulkanInfo {
            memory_idx: memory_type_index as u32,
            device_id: device.get_id(),
        });

        Ok(reqs)
    }

    fn allocate_memory(&mut self, reqs: ImageMemoryRequirements) -> RutabagaResult<RutabagaHandle> {
        let (unsafe_image, memory_requirements) = unsafe { self.create_image(reqs.info)? };

        let vulkan_info = reqs.vulkan_info.ok_or(RutabagaError::InvalidVulkanInfo)?;

        let device = if self.has_integrated_gpu {
            self.devices
                .get(&PhysicalDeviceType::IntegratedGpu)
                .ok_or(RutabagaError::InvalidGrallocGpuType)?
        } else {
            self.devices
                .get(&PhysicalDeviceType::DiscreteGpu)
                .ok_or(RutabagaError::InvalidGrallocGpuType)?
        };

        if vulkan_info.memory_idx as usize
            >= device
                .physical_device()
                .memory_properties()
                .memory_types
                .len()
        {
            return Err(RutabagaError::InvalidVulkanInfo);
        }

        let (export_handle_type, export_handle_types, rutabaga_type) =
            match device.enabled_extensions().ext_external_memory_dma_buf {
                true => (
                    ExternalMemoryHandleType::DmaBuf,
                    ExternalMemoryHandleTypes {
                        dma_buf: true,
                        ..ExternalMemoryHandleTypes::empty()
                    },
                    RUTABAGA_MEM_HANDLE_TYPE_DMABUF,
                ),
                false => (
                    ExternalMemoryHandleType::OpaqueFd,
                    ExternalMemoryHandleTypes {
                        opaque_fd: true,
                        ..ExternalMemoryHandleTypes::empty()
                    },
                    RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD,
                ),
            };

        let dedicated_allocation = match device.enabled_extensions().khr_dedicated_allocation {
            true => {
                if memory_requirements.prefer_dedicated {
                    Some(DedicatedAllocation::Image(&unsafe_image))
                } else {
                    None
                }
            }
            false => None,
        };

        let device_memory = DeviceMemory::allocate(
            device.clone(),
            MemoryAllocateInfo {
                allocation_size: reqs.size,
                memory_type_index: vulkan_info.memory_idx,
                dedicated_allocation,
                export_handle_types,
                ..Default::default()
            },
        )?;

        let descriptor = device_memory.export_fd(export_handle_type)?.into();

        Ok(RutabagaHandle {
            os_handle: descriptor,
            handle_type: rutabaga_type,
        })
    }

    /// Implementations must map the memory associated with the `resource_id` upon success.
    fn import_and_map(
        &mut self,
        handle: RutabagaHandle,
        vulkan_info: VulkanInfo,
        size: u64,
    ) -> RutabagaResult<Box<dyn MappedRegion>> {
        let device = self
            .device_by_id
            .get(&vulkan_info.device_id)
            .ok_or(RutabagaError::InvalidVulkanInfo)?;

        let device_memory = unsafe {
            VulkanoGralloc::import_memory(
                device.clone(),
                MemoryAllocateInfo {
                    allocation_size: size,
                    memory_type_index: vulkan_info.memory_idx,
                    ..Default::default()
                },
                handle,
            )?
        };

        let mapped_memory = MappedDeviceMemory::new(device_memory, 0..size)?;

        Ok(Box::new(VulkanoMapping::new(
            mapped_memory,
            size.try_into()?,
        )))
    }
}

// Vulkano should really define an universal type that wraps all these errors, say
// "VulkanoError(e)".
impl From<InstanceCreationError> for RutabagaError {
    fn from(e: InstanceCreationError) -> RutabagaError {
        RutabagaError::VkInstanceCreationError(e)
    }
}

impl From<ImageCreationError> for RutabagaError {
    fn from(e: ImageCreationError) -> RutabagaError {
        RutabagaError::VkImageCreationError(e)
    }
}

impl From<DeviceCreationError> for RutabagaError {
    fn from(e: DeviceCreationError) -> RutabagaError {
        RutabagaError::VkDeviceCreationError(e)
    }
}

impl From<DeviceMemoryError> for RutabagaError {
    fn from(e: DeviceMemoryError) -> RutabagaError {
        RutabagaError::VkDeviceMemoryError(e)
    }
}

impl From<MemoryMapError> for RutabagaError {
    fn from(e: MemoryMapError) -> RutabagaError {
        RutabagaError::VkMemoryMapError(e)
    }
}

impl From<LoadingError> for RutabagaError {
    fn from(e: LoadingError) -> RutabagaError {
        RutabagaError::VkLoadingError(e)
    }
}

impl From<VulkanError> for RutabagaError {
    fn from(e: VulkanError) -> RutabagaError {
        RutabagaError::VkError(e)
    }
}

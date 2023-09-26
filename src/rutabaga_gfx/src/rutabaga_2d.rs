// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! rutabaga_2d: Handles 2D virtio-gpu hypercalls.

use std::cmp::max;
use std::cmp::min;
use std::cmp::Ordering;
use std::io::IoSliceMut;

use crate::rutabaga_core::Rutabaga2DInfo;
use crate::rutabaga_core::RutabagaComponent;
use crate::rutabaga_core::RutabagaResource;
use crate::rutabaga_utils::*;

/// Transfers a resource from potentially many chunked src slices to a dst slice.
fn transfer_2d(
    resource_w: u32,
    resource_h: u32,
    rect_x: u32,
    rect_y: u32,
    rect_w: u32,
    rect_h: u32,
    dst_stride: u32,
    dst_offset: u64,
    mut dst: IoSliceMut,
    src_stride: u32,
    src_offset: u64,
    srcs: &[&[u8]],
) -> RutabagaResult<()> {
    if rect_w == 0 || rect_h == 0 {
        return Ok(());
    }

    checked_range!(checked_arithmetic!(rect_x + rect_w)?; <= resource_w)?;
    checked_range!(checked_arithmetic!(rect_y + rect_h)?; <= resource_h)?;

    let bytes_per_pixel = 4u64;

    let rect_x = rect_x as u64;
    let rect_y = rect_y as u64;
    let rect_w = rect_w as u64;
    let rect_h = rect_h as u64;

    let dst_stride = dst_stride as u64;
    let dst_offset = dst_offset;
    let dst_resource_offset = dst_offset + (rect_y * dst_stride) + (rect_x * bytes_per_pixel);

    let src_stride = src_stride as u64;
    let src_offset = src_offset;
    let src_resource_offset = src_offset + (rect_y * src_stride) + (rect_x * bytes_per_pixel);

    let mut next_src;
    let mut next_line;
    let mut current_height = 0u64;
    let mut srcs = srcs.iter();
    let mut src_opt = srcs.next();

    // Cumulative start offset of the current src.
    let mut src_start_offset = 0u64;
    while let Some(src) = src_opt {
        if current_height >= rect_h {
            break;
        }

        let src_size = src.len() as u64;

        // Cumulative end offset of the current src.
        let src_end_offset = checked_arithmetic!(src_start_offset + src_size)?;

        let src_line_vertical_offset = checked_arithmetic!(current_height * src_stride)?;
        let src_line_horizontal_offset = checked_arithmetic!(rect_w * bytes_per_pixel)?;

        // Cumulative start/end offsets of the next line to copy within all srcs.
        let src_line_start_offset =
            checked_arithmetic!(src_resource_offset + src_line_vertical_offset)?;
        let src_line_end_offset =
            checked_arithmetic!(src_line_start_offset + src_line_horizontal_offset)?;

        // Clamp the line start/end offset to be inside the current src.
        let src_copyable_start_offset = max(src_line_start_offset, src_start_offset);
        let src_copyable_end_offset = min(src_line_end_offset, src_end_offset);

        if src_copyable_start_offset < src_copyable_end_offset {
            let copyable_size =
                checked_arithmetic!(src_copyable_end_offset - src_copyable_start_offset)?;

            let offset_within_src = src_copyable_start_offset.saturating_sub(src_start_offset);

            match src_line_end_offset.cmp(&src_end_offset) {
                Ordering::Greater => {
                    next_src = true;
                    next_line = false;
                }
                Ordering::Equal => {
                    next_src = true;
                    next_line = true;
                }
                Ordering::Less => {
                    next_src = false;
                    next_line = true;
                }
            }

            let src_end = offset_within_src + copyable_size;
            let src_subslice = src
                .get(offset_within_src as usize..src_end as usize)
                .ok_or(RutabagaError::InvalidIovec)?;

            let dst_line_vertical_offset = checked_arithmetic!(current_height * dst_stride)?;
            let dst_line_horizontal_offset =
                checked_arithmetic!(src_copyable_start_offset - src_line_start_offset)?;
            let dst_line_offset =
                checked_arithmetic!(dst_line_vertical_offset + dst_line_horizontal_offset)?;
            let dst_start_offset = checked_arithmetic!(dst_resource_offset + dst_line_offset)?;

            let dst_end_offset = dst_start_offset + copyable_size;
            let dst_subslice = dst
                .get_mut(dst_start_offset as usize..dst_end_offset as usize)
                .ok_or(RutabagaError::InvalidIovec)?;

            dst_subslice.copy_from_slice(src_subslice);
        } else if src_line_start_offset >= src_start_offset {
            next_src = true;
            next_line = false;
        } else {
            next_src = false;
            next_line = true;
        };

        if next_src {
            src_start_offset = checked_arithmetic!(src_start_offset + src_size)?;
            src_opt = srcs.next();
        }

        if next_line {
            current_height += 1;
        }
    }

    Ok(())
}

pub struct Rutabaga2D {
    fence_handler: RutabagaFenceHandler,
}

impl Rutabaga2D {
    pub fn init(fence_handler: RutabagaFenceHandler) -> RutabagaResult<Box<dyn RutabagaComponent>> {
        Ok(Box::new(Rutabaga2D { fence_handler }))
    }
}

impl RutabagaComponent for Rutabaga2D {
    fn create_fence(&mut self, fence: RutabagaFence) -> RutabagaResult<()> {
        self.fence_handler.call(fence);
        Ok(())
    }

    fn create_3d(
        &self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> RutabagaResult<RutabagaResource> {
        // All virtio formats are 4 bytes per pixel.
        let resource_bpp = 4;
        let resource_stride = resource_bpp * resource_create_3d.width;
        let resource_size = (resource_stride as usize) * (resource_create_3d.height as usize);
        let info_2d = Rutabaga2DInfo {
            width: resource_create_3d.width,
            height: resource_create_3d.height,
            host_mem: vec![0; resource_size],
        };

        Ok(RutabagaResource {
            resource_id,
            handle: None,
            blob: false,
            blob_mem: 0,
            blob_flags: 0,
            map_info: None,
            info_2d: Some(info_2d),
            info_3d: None,
            vulkan_info: None,
            backing_iovecs: None,
            component_mask: 1 << (RutabagaComponentType::Rutabaga2D as u8),
            size: resource_size as u64,
            mapping: None,
        })
    }

    fn transfer_write(
        &self,
        _ctx_id: u32,
        resource: &mut RutabagaResource,
        transfer: Transfer3D,
    ) -> RutabagaResult<()> {
        if transfer.is_empty() {
            return Ok(());
        }

        let mut info_2d = resource
            .info_2d
            .take()
            .ok_or(RutabagaError::Invalid2DInfo)?;

        let iovecs = resource
            .backing_iovecs
            .take()
            .ok_or(RutabagaError::InvalidIovec)?;

        // All offical virtio_gpu formats are 4 bytes per pixel.
        let resource_bpp = 4;
        let mut src_slices = Vec::with_capacity(iovecs.len());
        for iovec in &iovecs {
            // Safe because Rutabaga users should have already checked the iovecs.
            let slice = unsafe { std::slice::from_raw_parts(iovec.base as *mut u8, iovec.len) };
            src_slices.push(slice);
        }

        let src_stride = resource_bpp * info_2d.width;
        let src_offset = transfer.offset;

        let dst_stride = resource_bpp * info_2d.width;
        let dst_offset = 0;

        transfer_2d(
            info_2d.width,
            info_2d.height,
            transfer.x,
            transfer.y,
            transfer.w,
            transfer.h,
            dst_stride,
            dst_offset,
            IoSliceMut::new(info_2d.host_mem.as_mut_slice()),
            src_stride,
            src_offset,
            &src_slices,
        )?;

        resource.info_2d = Some(info_2d);
        resource.backing_iovecs = Some(iovecs);
        Ok(())
    }

    fn transfer_read(
        &self,
        _ctx_id: u32,
        resource: &mut RutabagaResource,
        transfer: Transfer3D,
        buf: Option<IoSliceMut>,
    ) -> RutabagaResult<()> {
        let mut info_2d = resource
            .info_2d
            .take()
            .ok_or(RutabagaError::Invalid2DInfo)?;

        // All offical virtio_gpu formats are 4 bytes per pixel.
        let resource_bpp = 4;
        let src_stride = resource_bpp * info_2d.width;
        let src_offset = 0;
        let dst_offset = 0;

        let dst_slice = buf.ok_or(RutabagaError::SpecViolation(
            "need a destination slice for transfer read",
        ))?;

        transfer_2d(
            info_2d.width,
            info_2d.height,
            transfer.x,
            transfer.y,
            transfer.w,
            transfer.h,
            transfer.stride,
            dst_offset,
            dst_slice,
            src_stride,
            src_offset,
            &[info_2d.host_mem.as_mut_slice()],
        )?;

        resource.info_2d = Some(info_2d);
        Ok(())
    }
}

// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Generated with bindgen --allowlist-function='gbm_.*' --allowlist-type='gbm_.*' minigbm/gbm.h
// Then modified manually

#![cfg(feature = "minigbm")]
/* Added below line manually */
#![allow(dead_code, non_camel_case_types)]

/* Added below line manually */
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_uint;
use std::os::raw::c_void;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_device {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_bo {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_surface {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union gbm_bo_handle {
    pub ptr: *mut c_void,
    pub s32: i32,
    pub u32: u32,
    pub s64: i64,
    pub u64: u64,
    _bindgen_union_align: u64,
}
pub const GBM_BO_FORMAT_XRGB8888: gbm_bo_format = 0;
pub const GBM_BO_FORMAT_ARGB8888: gbm_bo_format = 1;
pub type gbm_bo_format = u32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_format_name_desc {
    pub name: [c_char; 5usize],
}
pub const GBM_BO_USE_SCANOUT: gbm_bo_flags = 1;
pub const GBM_BO_USE_CURSOR: gbm_bo_flags = 2;
pub const GBM_BO_USE_CURSOR_64X64: gbm_bo_flags = 2;
pub const GBM_BO_USE_RENDERING: gbm_bo_flags = 4;
pub const GBM_BO_USE_WRITE: gbm_bo_flags = 8;
pub const GBM_BO_USE_LINEAR: gbm_bo_flags = 16;
pub const GBM_BO_USE_TEXTURING: gbm_bo_flags = 32;
pub const GBM_BO_USE_CAMERA_WRITE: gbm_bo_flags = 64;
pub const GBM_BO_USE_CAMERA_READ: gbm_bo_flags = 128;
pub const GBM_BO_USE_PROTECTED: gbm_bo_flags = 256;
pub const GBM_BO_USE_SW_READ_OFTEN: gbm_bo_flags = 512;
pub const GBM_BO_USE_SW_READ_RARELY: gbm_bo_flags = 1024;
pub const GBM_BO_USE_SW_WRITE_OFTEN: gbm_bo_flags = 2048;
pub const GBM_BO_USE_SW_WRITE_RARELY: gbm_bo_flags = 4096;
pub const GBM_BO_USE_HW_VIDEO_DECODER: gbm_bo_flags = 8192;
pub const GBM_BO_USE_HW_VIDEO_ENCODER: gbm_bo_flags = 16384;
/* Added below line manually */
#[allow(non_camel_case_types)]
pub type gbm_bo_flags = u32;
/* Added below line manually */
#[link(name = "gbm")]
extern "C" {
    pub fn gbm_device_get_fd(gbm: *mut gbm_device) -> c_int;
}
extern "C" {
    pub fn gbm_device_get_backend_name(gbm: *mut gbm_device) -> *const c_char;
}
extern "C" {
    pub fn gbm_device_is_format_supported(gbm: *mut gbm_device, format: u32, usage: u32) -> c_int;
}
extern "C" {
    pub fn gbm_device_get_format_modifier_plane_count(
        gbm: *mut gbm_device,
        format: u32,
        modifier: u64,
    ) -> c_int;
}
extern "C" {
    pub fn gbm_device_destroy(gbm: *mut gbm_device);
}
extern "C" {
    pub fn gbm_create_device(fd: c_int) -> *mut gbm_device;
}
extern "C" {
    pub fn gbm_bo_create(
        gbm: *mut gbm_device,
        width: u32,
        height: u32,
        format: u32,
        flags: u32,
    ) -> *mut gbm_bo;
}
extern "C" {
    pub fn gbm_bo_create_with_modifiers(
        gbm: *mut gbm_device,
        width: u32,
        height: u32,
        format: u32,
        modifiers: *const u64,
        count: c_uint,
    ) -> *mut gbm_bo;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_import_fd_data {
    pub fd: c_int,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_import_fd_modifier_data {
    pub width: u32,
    pub height: u32,
    pub format: u32,
    pub num_fds: u32,
    pub fds: [c_int; 4usize],
    pub strides: [c_int; 4usize],
    pub offsets: [c_int; 4usize],
    pub modifier: u64,
}
extern "C" {
    pub fn gbm_bo_import(
        gbm: *mut gbm_device,
        type_: u32,
        buffer: *mut c_void,
        usage: u32,
    ) -> *mut gbm_bo;
}
pub const GBM_BO_TRANSFER_READ: gbm_bo_transfer_flags = 1;
pub const GBM_BO_TRANSFER_WRITE: gbm_bo_transfer_flags = 2;
pub const GBM_BO_TRANSFER_READ_WRITE: gbm_bo_transfer_flags = 3;

/* Added below line manually */
#[allow(non_camel_case_types)]
pub type gbm_bo_transfer_flags = u32;
extern "C" {
    pub fn gbm_bo_unmap(bo: *mut gbm_bo, map_data: *mut c_void);
}
extern "C" {
    pub fn gbm_bo_get_width(bo: *mut gbm_bo) -> u32;
}
extern "C" {
    pub fn gbm_bo_get_height(bo: *mut gbm_bo) -> u32;
}
extern "C" {
    pub fn gbm_bo_get_stride(bo: *mut gbm_bo) -> u32;
}
extern "C" {
    pub fn gbm_bo_get_stride_for_plane(bo: *mut gbm_bo, plane: usize) -> u32;
}
extern "C" {
    pub fn gbm_bo_get_format(bo: *mut gbm_bo) -> u32;
}
extern "C" {
    pub fn gbm_bo_get_bpp(bo: *mut gbm_bo) -> u32;
}
extern "C" {
    pub fn gbm_bo_get_offset(bo: *mut gbm_bo, plane: usize) -> u32;
}
extern "C" {
    pub fn gbm_bo_get_device(bo: *mut gbm_bo) -> *mut gbm_device;
}
extern "C" {
    pub fn gbm_bo_get_handle(bo: *mut gbm_bo) -> gbm_bo_handle;
}
extern "C" {
    pub fn gbm_bo_get_fd(bo: *mut gbm_bo) -> c_int;
}
extern "C" {
    pub fn gbm_bo_get_modifier(bo: *mut gbm_bo) -> u64;
}
extern "C" {
    pub fn gbm_bo_get_plane_count(bo: *mut gbm_bo) -> c_int;
}
extern "C" {
    pub fn gbm_bo_get_handle_for_plane(bo: *mut gbm_bo, plane: usize) -> gbm_bo_handle;
}
extern "C" {
    pub fn gbm_bo_write(bo: *mut gbm_bo, buf: *const c_void, count: usize) -> c_int;
}
extern "C" {
    pub fn gbm_bo_set_user_data(
        bo: *mut gbm_bo,
        data: *mut c_void,
        destroy_user_data: ::std::option::Option<
            unsafe extern "C" fn(arg1: *mut gbm_bo, arg2: *mut c_void),
        >,
    );
}
extern "C" {
    pub fn gbm_bo_get_user_data(bo: *mut gbm_bo) -> *mut c_void;
}
extern "C" {
    pub fn gbm_bo_destroy(bo: *mut gbm_bo);
}
extern "C" {
    pub fn gbm_surface_create(
        gbm: *mut gbm_device,
        width: u32,
        height: u32,
        format: u32,
        flags: u32,
    ) -> *mut gbm_surface;
}
extern "C" {
    pub fn gbm_surface_create_with_modifiers(
        gbm: *mut gbm_device,
        width: u32,
        height: u32,
        format: u32,
        modifiers: *const u64,
        count: c_uint,
    ) -> *mut gbm_surface;
}
extern "C" {
    pub fn gbm_surface_lock_front_buffer(surface: *mut gbm_surface) -> *mut gbm_bo;
}
extern "C" {
    pub fn gbm_surface_release_buffer(surface: *mut gbm_surface, bo: *mut gbm_bo);
}
extern "C" {
    pub fn gbm_surface_has_free_buffers(surface: *mut gbm_surface) -> c_int;
}
extern "C" {
    pub fn gbm_surface_destroy(surface: *mut gbm_surface);
}
extern "C" {
    pub fn gbm_format_get_name(gbm_format: u32, desc: *mut gbm_format_name_desc) -> *mut c_char;
}
extern "C" {
    pub fn gbm_bo_get_plane_size(bo: *mut gbm_bo, plane: usize) -> u32;
}
extern "C" {
    pub fn gbm_bo_get_plane_fd(bo: *mut gbm_bo, plane: usize) -> c_int;
}
extern "C" {
    pub fn gbm_bo_map(
        bo: *mut gbm_bo,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        flags: u32,
        stride: *mut u32,
        map_data: *mut *mut c_void,
        plane: usize,
    ) -> *mut c_void;
}
extern "C" {
    pub fn gbm_bo_map2(
        bo: *mut gbm_bo,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        flags: u32,
        stride: *mut u32,
        map_data: *mut *mut c_void,
        plane: c_int,
    ) -> *mut c_void;
}

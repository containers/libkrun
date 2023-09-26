// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Stub impplementation of the native interface of gfxstream_backend.so.
//!
//! This implementation is used to enable the gfxstream feature of crosvm to be compiled without
//! gfxstream_backend.so available. It is only used for testing purposes and not functional
//! at runtime.

#![cfg(feature = "gfxstream_stub")]

use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_uint;
use std::os::raw::c_void;

use crate::generated::virgl_renderer_bindings::iovec;
use crate::gfxstream::stream_renderer_box;
use crate::gfxstream::stream_renderer_command;
use crate::gfxstream::stream_renderer_create_blob;
use crate::gfxstream::stream_renderer_fence;
use crate::gfxstream::stream_renderer_handle;
use crate::gfxstream::stream_renderer_param;
use crate::gfxstream::stream_renderer_resource_create_args;
use crate::gfxstream::stream_renderer_vulkan_info;

#[no_mangle]
extern "C" fn stream_renderer_init(
    _stream_renderer_params: *mut stream_renderer_param,
    _num_params: u64,
) -> c_int {
    unimplemented!();
}

#[no_mangle]
extern "C" fn stream_renderer_teardown() {
    unimplemented!();
}

#[no_mangle]
extern "C" fn stream_renderer_resource_create(
    _args: *mut stream_renderer_resource_create_args,
    _iov: *mut iovec,
    _num_iovs: u32,
) -> c_int {
    unimplemented!();
}

#[no_mangle]
extern "C" fn stream_renderer_resource_unref(_res_handle: u32) {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_context_destroy(_handle: u32) {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_transfer_read_iov(
    _handle: u32,
    _ctx_id: u32,
    _level: u32,
    _stride: u32,
    _layer_stride: u32,
    _box_: *mut stream_renderer_box,
    _offset: u64,
    _iov: *mut iovec,
    _iovec_cnt: c_int,
) -> c_int {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_transfer_write_iov(
    _handle: u32,
    _ctx_id: u32,
    _level: c_int,
    _stride: u32,
    _layer_stride: u32,
    _box_: *mut stream_renderer_box,
    _offset: u64,
    _iovec: *mut iovec,
    _iovec_cnt: c_uint,
) -> c_int {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_submit_cmd(_cmd: *const stream_renderer_command) -> c_int {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_resource_attach_iov(
    _res_handle: c_int,
    _iov: *mut iovec,
    _num_iovs: c_int,
) -> c_int {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_resource_detach_iov(
    _res_handle: c_int,
    _iov: *mut *mut iovec,
    _num_iovs: *mut c_int,
) {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_ctx_attach_resource(_ctx_id: c_int, _res_handle: c_int) {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_ctx_detach_resource(_ctx_id: c_int, _res_handle: c_int) {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_get_cap_set(_set: u32, _max_ver: *mut u32, _max_size: *mut u32) {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_fill_caps(_set: u32, _version: u32, _caps: *mut c_void) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn stream_renderer_flush(_res_handle: u32) {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_create_blob(
    _ctx_id: u32,
    _res_handle: u32,
    _create_blob: *const stream_renderer_create_blob,
    _iovecs: *const iovec,
    _num_iovs: u32,
    _handle: *const stream_renderer_handle,
) -> c_int {
    unimplemented!();
}

#[no_mangle]
extern "C" fn stream_renderer_export_blob(
    _res_handle: u32,
    _handle: *mut stream_renderer_handle,
) -> c_int {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_resource_map(
    _res_handle: u32,
    _map: *mut *mut c_void,
    _out_size: *mut u64,
) -> c_int {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_resource_unmap(_res_handle: u32) -> c_int {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_resource_map_info(_res_handle: u32, _map_info: *mut u32) -> c_int {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_vulkan_info(
    _res_handle: u32,
    _vulkan_info: *mut stream_renderer_vulkan_info,
) -> c_int {
    unimplemented!();
}
#[no_mangle]
extern "C" fn stream_renderer_context_create(
    _handle: u32,
    _nlen: u32,
    _name: *const c_char,
    _context_init: u32,
) -> c_int {
    unimplemented!();
}
#[no_mangle]

extern "C" fn stream_renderer_create_fence(_fence: *const stream_renderer_fence) -> c_int {
    unimplemented!();
}

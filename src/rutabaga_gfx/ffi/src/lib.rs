// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

///! C-bindings for the rutabaga_gfx crate
extern crate rutabaga_gfx;

use std::convert::TryInto;
use std::ffi::CStr;
use std::ffi::CString;
use std::io::IoSliceMut;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::panic::catch_unwind;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::ptr::copy_nonoverlapping;
use std::ptr::null;
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use std::slice::from_raw_parts_mut;
use std::sync::Mutex;

use libc::iovec;
use libc::EINVAL;
use libc::ESRCH;
use once_cell::sync::OnceCell;
use rutabaga_gfx::*;

const NO_ERROR: i32 = 0;
const RUTABAGA_WSI_SURFACELESS: u64 = 1;

static S_DEBUG_HANDLER: OnceCell<Mutex<RutabagaDebugHandler>> = OnceCell::new();

fn log_error(debug_string: String) {
    // Although this should be only called from a single-thread environment, add locking to
    // to reduce the amount of unsafe code blocks.
    if let Some(ref handler_mutex) = S_DEBUG_HANDLER.get() {
        let cstring = CString::new(debug_string.as_str()).expect("CString creation failed");

        let debug = RutabagaDebug {
            debug_type: RUTABAGA_DEBUG_ERROR,
            message: cstring.as_ptr(),
        };

        let handler = handler_mutex.lock().unwrap();
        handler.call(debug);
    }
}

fn return_result<T>(result: RutabagaResult<T>) -> i32 {
    if let Err(e) = result {
        log_error(e.to_string());
        -EINVAL
    } else {
        NO_ERROR
    }
}

macro_rules! return_on_error {
    ($result:expr) => {
        match $result {
            Ok(t) => t,
            Err(e) => {
                log_error(e.to_string());
                return -EINVAL;
            }
        }
    };
}

#[allow(non_camel_case_types)]
type rutabaga = Rutabaga;

#[allow(non_camel_case_types)]
type rutabaga_create_blob = ResourceCreateBlob;

#[allow(non_camel_case_types)]
type rutabaga_create_3d = ResourceCreate3D;

#[allow(non_camel_case_types)]
type rutabaga_transfer = Transfer3D;

#[allow(non_camel_case_types)]
type rutabaga_fence = RutabagaFence;

#[allow(non_camel_case_types)]
type rutabaga_debug = RutabagaDebug;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct rutabaga_iovecs {
    pub iovecs: *mut iovec,
    pub num_iovecs: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct rutabaga_handle {
    pub os_handle: i64,
    pub handle_type: u32,
}

#[repr(C)]
pub struct rutabaga_mapping {
    pub ptr: *mut c_void,
    pub size: u64,
}

#[repr(C)]
pub struct rutabaga_channel {
    pub channel_name: *const c_char,
    pub channel_type: u32,
}

#[repr(C)]
pub struct rutabaga_channels {
    pub channels: *const rutabaga_channel,
    pub num_channels: usize,
}

#[repr(C)]
pub struct rutabaga_command {
    pub ctx_id: u32,
    pub cmd_size: u32,
    pub cmd: *mut u8,
    pub num_in_fences: u32,
    pub fence_ids: *mut u64,
}

#[allow(non_camel_case_types)]
pub type rutabaga_fence_callback = extern "C" fn(user_data: u64, fence: &rutabaga_fence);

#[allow(non_camel_case_types)]
pub type rutabaga_debug_callback = extern "C" fn(user_data: u64, debug: &rutabaga_debug);

#[repr(C)]
pub struct rutabaga_builder<'a> {
    pub user_data: u64,
    pub capset_mask: u64,
    pub wsi: u64,
    pub fence_cb: rutabaga_fence_callback,
    pub debug_cb: Option<rutabaga_debug_callback>,
    pub channels: Option<&'a rutabaga_channels>,
}

fn create_ffi_fence_handler(
    user_data: u64,
    fence_cb: rutabaga_fence_callback,
) -> RutabagaFenceHandler {
    RutabagaFenceHandler::new(move |completed_fence| fence_cb(user_data, &completed_fence))
}

fn create_ffi_debug_handler(
    user_data: u64,
    debug_cb: rutabaga_debug_callback,
) -> RutabagaDebugHandler {
    RutabagaDebugHandler::new(move |rutabaga_debug| debug_cb(user_data, &rutabaga_debug))
}

#[no_mangle]
/// # Safety
/// - `capset_names` must be a null-terminated C-string.
pub unsafe extern "C" fn rutabaga_calculate_capset_mask(
    capset_names: *const c_char,
    capset_mask: &mut u64,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if capset_names == null() {
            return -EINVAL;
        }

        let c_str_slice = CStr::from_ptr(capset_names);
        let result = c_str_slice.to_str();
        let str_slice = return_on_error!(result);
        *capset_mask = rutabaga_gfx::calculate_capset_mask(str_slice.split(':'));
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - If `(*builder).channels` is not null, the caller must ensure `(*channels).channels` points to
///   a valid array of `struct rutabaga_channel` of size `(*channels).num_channels`.
/// - The `channel_name` field of `struct rutabaga_channel` must be a null-terminated C-string.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_init(builder: &rutabaga_builder, ptr: &mut *mut rutabaga) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let fence_handler = create_ffi_fence_handler((*builder).user_data, (*builder).fence_cb);
        let mut debug_handler_opt: Option<RutabagaDebugHandler> = None;

        if let Some(func) = (*builder).debug_cb {
            let debug_handler = create_ffi_debug_handler((*builder).user_data, func);
            S_DEBUG_HANDLER
                .set(Mutex::new(debug_handler.clone()))
                .expect("once_cell set failed");
            debug_handler_opt = Some(debug_handler);
        }

        let mut rutabaga_channels_opt = None;
        if let Some(channels) = (*builder).channels {
            let mut rutabaga_channels: Vec<RutabagaChannel> = Vec::new();
            let channels_slice = from_raw_parts(channels.channels, channels.num_channels);

            for channel in channels_slice {
                let c_str_slice = CStr::from_ptr(channel.channel_name);
                let result = c_str_slice.to_str();
                let str_slice = return_on_error!(result);
                let string = str_slice.to_owned();
                let path = PathBuf::from(&string);

                rutabaga_channels.push(RutabagaChannel {
                    base_channel: path,
                    channel_type: channel.channel_type,
                });
            }

            rutabaga_channels_opt = Some(rutabaga_channels);
        }

        let mut component_type = RutabagaComponentType::CrossDomain;
        if (*builder).capset_mask == 0 {
            component_type = RutabagaComponentType::Rutabaga2D;
        }

        let rutabaga_wsi = match (*builder).wsi {
            RUTABAGA_WSI_SURFACELESS => RutabagaWsi::Surfaceless,
            _ => return -EINVAL,
        };

        let result = RutabagaBuilder::new(component_type, (*builder).capset_mask)
            .set_use_external_blob(false)
            .set_use_egl(true)
            .set_wsi(rutabaga_wsi)
            .set_debug_handler(debug_handler_opt)
            .set_rutabaga_channels(rutabaga_channels_opt)
            .build(fence_handler, None);

        let rtbg = return_on_error!(result);
        *ptr = Box::into_raw(Box::new(rtbg)) as _;
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - `ptr` must have been created by `rutabaga_init`.
#[no_mangle]
pub extern "C" fn rutabaga_finish(ptr: &mut *mut rutabaga) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        unsafe { Box::from_raw(*ptr) };
        *ptr = null_mut();
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_get_num_capsets(ptr: &mut rutabaga, num_capsets: &mut u32) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        *num_capsets = ptr.get_num_capsets();
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_get_capset_info(
    ptr: &mut rutabaga,
    capset_index: u32,
    capset_id: &mut u32,
    capset_version: &mut u32,
    capset_size: &mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.get_capset_info(capset_index);
        let info = return_on_error!(result);
        *capset_id = info.0;
        *capset_version = info.1;
        *capset_size = info.2;
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - `capset` must point an array of bytes of size `capset_size`.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_get_capset(
    ptr: &mut rutabaga,
    capset_id: u32,
    version: u32,
    capset: *mut u8,
    capset_size: u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let size: usize = capset_size.try_into().map_err(|_e| -EINVAL).unwrap();
        let result = ptr.get_capset(capset_id, version);
        let vec = return_on_error!(result);
        copy_nonoverlapping(vec.as_ptr(), capset, size);
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_context_create(
    ptr: &mut rutabaga,
    ctx_id: u32,
    context_init: u32,
    context_name: *const c_char,
    context_name_len: u32,
) -> i32 {
    let mut name: Option<&str> = None;
    if !context_name.is_null() && context_name_len > 0 {
        // Safe because context_name is not NULL and len is a positive integer, so the caller
        // is expected to provide a valid pointer to an array of bytes at least as long as the
        // passed length. If the provided byte array doesn't contain valid utf-8, name will be
        // None.
        let view = unsafe {
            std::slice::from_raw_parts(context_name as *const u8, context_name_len as usize)
        };
        name = std::str::from_utf8(view).ok();
    }

    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.create_context(ctx_id, context_init, name);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_context_destroy(ptr: &mut rutabaga, ctx_id: u32) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.destroy_context(ctx_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_context_attach_resource(
    ptr: &mut rutabaga,
    ctx_id: u32,
    resource_id: u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.context_attach_resource(ctx_id, resource_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_context_detach_resource(
    ptr: &mut rutabaga,
    ctx_id: u32,
    resource_id: u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.context_detach_resource(ctx_id, resource_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_create_3d(
    ptr: &mut rutabaga,
    resource_id: u32,
    create_3d: &rutabaga_create_3d,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.resource_create_3d(resource_id, *create_3d);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - If `iovecs` is not null, the caller must ensure `(*iovecs).iovecs` points to a valid array of
///   iovecs of size `(*iovecs).num_iovecs`.
/// - Each iovec must point to valid memory starting at `iov_base` with length `iov_len`.
/// - Each iovec must valid until the resource's backing is explictly detached or the resource is
///   is unreferenced.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_resource_attach_backing(
    ptr: &mut rutabaga,
    resource_id: u32,
    iovecs: &rutabaga_iovecs,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let slice = from_raw_parts((*iovecs).iovecs, (*iovecs).num_iovecs);
        let vecs = slice
            .iter()
            .map(|iov| RutabagaIovec {
                base: iov.iov_base,
                len: iov.iov_len,
            })
            .collect();

        let result = ptr.attach_backing(resource_id, vecs);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_detach_backing(ptr: &mut rutabaga, resource_id: u32) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.detach_backing(resource_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - If `iovecs` is not null, the caller must ensure `(*iovecs).iovecs` points to a valid array of
///   iovecs of size `(*iovecs).num_iovecs`.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_resource_transfer_read(
    ptr: &mut rutabaga,
    ctx_id: u32,
    resource_id: u32,
    transfer: &rutabaga_transfer,
    buf: Option<&iovec>,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let mut slice_opt = None;
        if let Some(iovec) = buf {
            slice_opt = Some(IoSliceMut::new(std::slice::from_raw_parts_mut(
                iovec.iov_base as *mut u8,
                iovec.iov_len,
            )));
        }

        let result = ptr.transfer_read(ctx_id, resource_id, *transfer, slice_opt);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_transfer_write(
    ptr: &mut rutabaga,
    ctx_id: u32,
    resource_id: u32,
    transfer: &rutabaga_transfer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.transfer_write(ctx_id, resource_id, *transfer);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - If `iovecs` is not null, the caller must ensure `(*iovecs).iovecs` points to a valid array of
///   iovecs of size `(*iovecs).num_iovecs`.
/// - If `handle` is not null, the caller must ensure it is a valid OS-descriptor.  Ownership is
///   transfered to rutabaga.
/// - Each iovec must valid until the resource's backing is explictly detached or the resource is
///   is unreferenced.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_resource_create_blob(
    ptr: &mut rutabaga,
    ctx_id: u32,
    resource_id: u32,
    create_blob: &rutabaga_create_blob,
    iovecs: Option<&rutabaga_iovecs>,
    handle: Option<&rutabaga_handle>,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let mut iovecs_opt: Option<Vec<RutabagaIovec>> = None;
        if let Some(iovs) = iovecs {
            let slice = from_raw_parts((*iovs).iovecs, (*iovs).num_iovecs);
            let vecs = slice
                .iter()
                .map(|iov| RutabagaIovec {
                    base: iov.iov_base,
                    len: iov.iov_len,
                })
                .collect();
            iovecs_opt = Some(vecs);
        }

        let mut handle_opt: Option<RutabagaHandle> = None;
        if let Some(hnd) = handle {
            handle_opt = Some(RutabagaHandle {
                os_handle: RutabagaDescriptor::from_raw_descriptor(
                    (*hnd).os_handle.try_into().unwrap(),
                ),
                handle_type: (*hnd).handle_type,
            });
        }

        let result =
            ptr.resource_create_blob(ctx_id, resource_id, *create_blob, iovecs_opt, handle_opt);

        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_unref(ptr: &mut rutabaga, resource_id: u32) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.unref_resource(resource_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// Caller owns raw descriptor on success and is responsible for closing it.
#[no_mangle]
pub extern "C" fn rutabaga_resource_export_blob(
    ptr: &mut rutabaga,
    resource_id: u32,
    handle: &mut rutabaga_handle,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.export_blob(resource_id);
        let hnd = return_on_error!(result);

        (*handle).handle_type = hnd.handle_type;
        (*handle).os_handle = hnd.os_handle.into_raw_descriptor() as i64;
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_map(
    ptr: &mut rutabaga,
    resource_id: u32,
    mapping: &mut rutabaga_mapping,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.map(resource_id);
        let internal_map = return_on_error!(result);
        (*mapping).ptr = internal_map.ptr as *mut c_void;
        (*mapping).size = internal_map.size;
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_unmap(ptr: &mut rutabaga, resource_id: u32) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.unmap(resource_id);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_resource_map_info(
    ptr: &mut rutabaga,
    resource_id: u32,
    map_info: &mut u32,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.map_info(resource_id);
        *map_info = return_on_error!(result);
        NO_ERROR
    }))
    .unwrap_or(-ESRCH)
}

/// # Safety
/// - `commands` must point to a contiguous memory region of `size` bytes.
#[no_mangle]
pub unsafe extern "C" fn rutabaga_submit_command(
    ptr: &mut rutabaga,
    cmd: &rutabaga_command,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let cmd_slice = from_raw_parts_mut(cmd.cmd, cmd.cmd_size as usize);
        let fence_ids = from_raw_parts(cmd.fence_ids, cmd.num_in_fences as usize);
        let result = ptr.submit_command(cmd.ctx_id, cmd_slice, fence_ids);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

#[no_mangle]
pub extern "C" fn rutabaga_create_fence(ptr: &mut rutabaga, fence: &rutabaga_fence) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let result = ptr.create_fence(*fence);
        return_result(result)
    }))
    .unwrap_or(-ESRCH)
}

mod rust_to_c;
pub use rust_to_c::*;
mod c_to_rust;
pub use c_to_rust::*;

use bitflags::bitflags;
use std::ffi::c_void;
use thiserror::Error;

bitflags! {
    pub struct DisplayFeatures: u32 {
        const BASIC_FRAMEBUFFER = 1;
    }
}

#[derive(Error, Debug)]
#[repr(i32)]
pub enum DisplayBackendError {
    #[error("Backend implementation error")]
    InternalError = -1,
    #[error("Method not supported")]
    MethodNotSupported = -2,
    #[error("Invalid scanout id")]
    InvalidScanoutId = -3,
    #[error("Invalid parameter")]
    InvalidParam = -4,
}

pub type CreateFn = extern "C" fn(
    instance: *mut *mut c_void,
    userdata: *const c_void,
    _reserved: *const c_void,
) -> i32;
pub type DestroyFn = extern "C" fn(instance: *mut c_void) -> i32;
pub type ConfigureScanoutFn = extern "C" fn(
    instance: *mut c_void,
    scanout_id: u32,
    display_width: u32,
    display_height: u32,
    width: u32,
    height: u32,
    format: u32,
) -> i32;
pub type DisableScanoutFn = extern "C" fn(instance: *mut c_void, scanout_id: u32) -> i32;
pub type AllocFrameFn = extern "C" fn(
    instance: *mut c_void,
    scanout_id: u32,
    buffer: *mut *mut u8,
    buffer_size: *mut usize,
) -> i32;
pub type PresentFrameFn =
    extern "C" fn(instance: *mut c_void, scanout_id: u32, frame_id: u32) -> i32;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DisplayBackendVtable {
    pub destroy_fn: Option<DestroyFn>,

    // Methods required for BASIC_FRAMEBUFFER feature:
    pub configure_scanout_fn: Option<ConfigureScanoutFn>,
    pub disable_scanout_fn: Option<DisableScanoutFn>,
    pub alloc_frame_fn: Option<AllocFrameFn>,
    pub present_frame_fn: Option<PresentFrameFn>,
}

impl DisplayBackendVtable {
    pub fn implements_features(&self, features: DisplayFeatures) -> bool {
        if features.contains(DisplayFeatures::BASIC_FRAMEBUFFER) {
            self.configure_scanout_fn.is_some()
                && self.disable_scanout_fn.is_some()
                && self.alloc_frame_fn.is_some()
                && self.present_frame_fn.is_some()
        } else {
            true
        }
    }
}

use crate::{DisplayBackend, DisplayBackendError, DisplayBackendVtable};
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr;
use std::ptr::{null, null_mut};

pub trait DisplayBackendNew<T> {
    fn new(userdata: Option<&T>) -> Self;
}

pub trait DisplayBackendBasicFramebuffer {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: u32,
    ) -> Result<(), DisplayBackendError>;

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError>;

    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError>;

    fn present_frame(&mut self, scanout_id: u32, frame_id: u32) -> Result<(), DisplayBackendError>;
}

pub trait IntoDisplayBackend<T> {
    fn into_display_backend(userdata: Option<&T>) -> DisplayBackend;
}

impl<T, I: DisplayBackendBasicFramebuffer + DisplayBackendNew<T>> IntoDisplayBackend<T> for I {
    fn into_display_backend(userdata: Option<&T>) -> DisplayBackend {
        extern "C" fn create_fn<T, I: DisplayBackendNew<T>>(
            instance: *mut *mut c_void,
            userdata: *const c_void,
            _reserved: *const c_void,
        ) -> i32 {
            unsafe {
                assert_ne!(
                    instance,
                    null_mut(),
                    "Pointer to location where to create instance cannot be null"
                );
                let userdata_ref = (userdata as *const T).as_ref();
                *(instance as *mut *mut I) = Box::into_raw(Box::new(I::new(userdata_ref)));
            }
            0
        }

        extern "C" fn destroy_fn<I>(instance: *mut c_void) -> i32 {
            drop(unsafe { Box::from_raw(instance as *mut I) });
            0
        }

        extern "C" fn cast_instance<'a, I: DisplayBackendBasicFramebuffer>(
            instance: *mut c_void,
        ) -> &'a mut I {
            assert_ne!(instance, null_mut());
            unsafe { &mut *(instance as *mut I) }
        }

        extern "C" fn configure_scanout_fn<I: DisplayBackendBasicFramebuffer>(
            instance: *mut c_void,
            scanout_id: u32,
            display_width: u32,
            display_height: u32,
            width: u32,
            height: u32,
            format: u32,
        ) -> i32 {
            from_rust_result(cast_instance::<I>(instance).configure_scanout(
                scanout_id,
                display_width,
                display_height,
                width,
                height,
                format,
            ))
        }

        extern "C" fn disable_scanout_fb<I: DisplayBackendBasicFramebuffer>(
            instance: *mut c_void,
            scanout_id: u32,
        ) -> i32 {
            from_rust_result(cast_instance::<I>(instance).disable_scanout(scanout_id))
        }

        extern "C" fn alloc_frame<I: DisplayBackendBasicFramebuffer>(
            instance: *mut c_void,
            scanout_id: u32,
            buffer: *mut *mut u8,
            buffer_size: *mut usize,
        ) -> i32 {
            match cast_instance::<I>(instance).alloc_frame(scanout_id) {
                Ok((frame_id, allocated_buffer)) => {
                    unsafe {
                        *buffer_size = allocated_buffer.len();
                        *buffer = allocated_buffer.as_mut_ptr();
                    }
                    frame_id as i32
                }
                Err(e) => e as i32,
            }
        }

        extern "C" fn present_frame<I: DisplayBackendBasicFramebuffer>(
            instance: *mut c_void,
            scanout_id: u32,
            frame_id: u32,
        ) -> i32 {
            from_rust_result(cast_instance::<I>(instance).present_frame(scanout_id, frame_id))
        }

        DisplayBackend {
            phantom: PhantomData,
            userdata: userdata.map_or(null(), |t| ptr::from_ref(t) as *const c_void),
            create_fn: Some(create_fn::<T, I>),
            vtable: DisplayBackendVtable {
                destroy_fn: Some(destroy_fn::<I>),
                configure_scanout_fn: Some(configure_scanout_fn::<I>),
                present_frame_fn: Some(present_frame::<I>),
                alloc_frame_fn: Some(alloc_frame::<I>),
                disable_scanout_fn: Some(disable_scanout_fb::<I>),
            },
        }
    }
}

fn from_rust_result(result: Result<(), DisplayBackendError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

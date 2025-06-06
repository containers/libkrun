use crate::{CreateFn, DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendVtable};
use log::error;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::{null, null_mut, slice_from_raw_parts_mut};

#[macro_export]
macro_rules! into_rust_result {
    ($expr:expr) => {
        into_rust_result!($expr,
            0 => Ok(()),
            code @ 0.. => {
                log::warn!("{}: Unknown OK result code: {code}", stringify!($expr));
                Ok(())
            }
        )
    };
    ($expr:expr, $($pat:pat $(if $pat_guard:expr)? => $pat_expr:expr),+ ) => {
        match $expr {
            $($pat $(if $pat_guard)? => $pat_expr,)+
            -1 => Err(DisplayBackendError::InternalError),
            -3 => Err(DisplayBackendError::InvalidScanoutId),
            -4 => Err(DisplayBackendError::InvalidParam),
            code @ i32::MIN.. => {
                log::warn!("{}: Unknown error result code: {code}", stringify!($expr));
                Err(DisplayBackendError::InternalError)
            }
        }
    };
}

macro_rules! method_call {
    ($self:ident.$method:ident($($args:expr),*) ) => {
        $self.vtable
            .$method
            .ok_or(DisplayBackendError::MethodNotSupported)?( $self.instance, $($args),* )
    };
}

// Note: by design DisplayBackendInstance is tied to the thread that created it. (!Send, !Sync).
// This is to allow for easy and efficient implementation of the trait!
pub struct DisplayBackendInstance {
    instance: *mut c_void,
    vtable: DisplayBackendVtable,
}

impl Drop for DisplayBackendInstance {
    fn drop(&mut self) {
        let Some(delete_fn) = self.vtable.destroy_fn else {
            return;
        };

        if let Err(e) = into_rust_result!(delete_fn(self.instance)) {
            error!("Failed to destroy display instance: {e}");
        }
    }
}

impl DisplayBackendBasicFramebuffer for DisplayBackendInstance {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: u32,
    ) -> Result<(), DisplayBackendError> {
        into_rust_result!(method_call! {
        self.configure_scanout_fn(
            scanout_id,
            display_width,
            display_height,
            width,
            height,
            format
        )
        })
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        into_rust_result! {
            method_call! {
                self.disable_scanout_fn(scanout_id)
            }
        }
    }

    // Soundness note: this method has to take &mut self in order for the lifetime of the returned
    // slice to be tied to self. This way the returned slice cannot stay borrowed once another method
    // on self is called.
    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        let mut buffer: *mut u8 = null_mut();
        let mut buffer_len: usize = 0;
        let frame_id = into_rust_result! {
            method_call! {
                self.alloc_frame_fn(scanout_id, &raw mut buffer, &raw mut buffer_len)
            },
            result @ 0.. => Ok(result as u32)
        }?;

        assert_ne!(buffer, null_mut());
        assert_ne!(buffer_len, 0);
        // SAFETY: We have obtained the buffer and buffer_len from the display impl. Because
        //         the alloc_frame_fn return an error we assume they should be valid.
        let buffer = unsafe {
            slice_from_raw_parts_mut(buffer, buffer_len)
                .as_mut()
                .unwrap()
        };
        Ok((frame_id, buffer))
    }

    fn present_frame(&mut self, scanout_id: u32, frame_id: u32) -> Result<(), DisplayBackendError> {
        into_rust_result! {
            method_call!{
                self.present_frame_fn(scanout_id, frame_id)
            }
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct DisplayBackend<'userdata> {
    // TODO: probably remove the lifetime? or make it 'static always?
    pub phantom: PhantomData<&'userdata c_void>,
    pub userdata: *const c_void,
    pub create_fn: Option<CreateFn>,
    pub vtable: DisplayBackendVtable,
}

impl<'a> DisplayBackend<'a> {
    pub fn create_instance(&self) -> Result<DisplayBackendInstance, DisplayBackendError> {
        let mut instance = null_mut();
        if let Some(create_fn) = self.create_fn {
            into_rust_result!(create_fn(&raw mut instance, self.userdata, null()))?;
        }
        Ok(DisplayBackendInstance {
            instance,
            vtable: self.vtable,
        })
    }
}

unsafe impl<'a> Send for DisplayBackend<'a> {}

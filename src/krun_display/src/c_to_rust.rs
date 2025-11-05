use crate::{
    DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayFeatures, DisplayVtable, Rect,
    ResourceFormat, header,
};
use log::{error, warn};
use static_assertions::assert_not_impl_any;
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

pub struct DisplayBackendInstance {
    instance: *mut c_void,
    vtable: DisplayVtable,
    features: DisplayFeatures,
}

// By design the struct is !Send and !Sync to allow for the implementation to safely assume that
// the methods are always called on the GPU worker thread
assert_not_impl_any!(DisplayBackendInstance: Sync, Send);

impl Drop for DisplayBackendInstance {
    fn drop(&mut self) {
        // SAFETY: destroy is at the same offset in both vtable variants
        let destroy_fn = unsafe { self.vtable.basic_framebuffer.destroy };

        let Some(destroy_fn) = destroy_fn else {
            return;
        };

        if let Err(e) = into_rust_result!(unsafe { destroy_fn(self.instance) }) {
            error!("Failed to destroy krun_gtk_display instance: {e}");
        }
    }
}

impl DisplayBackendInstance {
    pub fn supports_dmabuf(&self) -> bool {
        self.features.contains(DisplayFeatures::DMABUF_CONSUMER)
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
        format: ResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        // SAFETY: configure_scanout is at the same offset in both vtable variants
        let configure_scanout = unsafe { self.vtable.basic_framebuffer.configure_scanout };

        into_rust_result!(unsafe {
            configure_scanout.ok_or(DisplayBackendError::MethodNotSupported)?(
                self.instance,
                scanout_id,
                display_width,
                display_height,
                width,
                height,
                format as u32,
            )
        })
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        // SAFETY: disable_scanout is at the same offset in both vtable variants
        let disable_scanout = unsafe { self.vtable.basic_framebuffer.disable_scanout };

        into_rust_result!(unsafe {
            disable_scanout.ok_or(DisplayBackendError::MethodNotSupported)?(
                self.instance,
                scanout_id,
            )
        })
    }

    // Soundness note: this method has to take &mut self in order for the lifetime of the returned
    // slice to be tied to self. This way the returned slice cannot stay borrowed once another method
    // on self is called.
    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        // SAFETY: alloc_frame is at the same offset in both vtable variants
        let alloc_frame = unsafe { self.vtable.basic_framebuffer.alloc_frame };

        let mut buffer: *mut u8 = null_mut();
        let mut buffer_len: usize = 0;
        let frame_id = into_rust_result! {
            unsafe {
                alloc_frame
                    .ok_or(DisplayBackendError::MethodNotSupported)?(
                    self.instance,
                    scanout_id,
                    &raw mut buffer,
                    &raw mut buffer_len
                )
            },
            result @ 0.. => Ok(result as u32)
        }?;

        assert_ne!(buffer, null_mut());
        assert_ne!(buffer_len, 0);
        let buffer = unsafe {
            slice_from_raw_parts_mut(buffer, buffer_len)
                .as_mut()
                .unwrap()
        };
        Ok((frame_id, buffer))
    }

    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        // SAFETY: present_frame is at the same offset in both vtable variants
        let present_frame = unsafe { self.vtable.basic_framebuffer.present_frame };

        let rect_ptr = rect.map_or(null(), std::ptr::from_ref);
        into_rust_result!(unsafe {
            present_frame.ok_or(DisplayBackendError::MethodNotSupported)?(
                self.instance,
                scanout_id,
                frame_id,
                rect_ptr,
            )
        })
    }
}

impl DisplayBackendInstance {
    pub fn import_dmabuf(
        &mut self,
        dmabuf_export: &crate::DmabufExport,
    ) -> Result<u32, DisplayBackendError> {
        if !self.features.contains(DisplayFeatures::DMABUF_CONSUMER) {
            return Err(DisplayBackendError::MethodNotSupported);
        }

        into_rust_result! {
            unsafe {
                self.vtable
                    .dmabuf
                    .import_dmabuf
                    .ok_or(DisplayBackendError::MethodNotSupported)?(
                    self.instance,
                    dmabuf_export as *const _,
                )
            },
            result @ 0.. => Ok(result as u32)
        }
    }

    pub fn unref_dmabuf(&mut self, dmabuf_id: u32) -> Result<(), DisplayBackendError> {
        if !self.features.contains(DisplayFeatures::DMABUF_CONSUMER) {
            return Err(DisplayBackendError::MethodNotSupported);
        }

        into_rust_result!(unsafe {
            self.vtable
                .dmabuf
                .unref_dmabuf
                .ok_or(DisplayBackendError::MethodNotSupported)?(
                self.instance, dmabuf_id
            )
        })
    }

    pub fn configure_scanout_dmabuf(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        dmabuf_id: u32,
        src_rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        if !self.features.contains(DisplayFeatures::DMABUF_CONSUMER) {
            return Err(DisplayBackendError::MethodNotSupported);
        }

        let rect_ptr = src_rect.map_or(null(), std::ptr::from_ref);
        into_rust_result!(unsafe {
            self.vtable
                .dmabuf
                .configure_scanout_dmabuf
                .ok_or(DisplayBackendError::MethodNotSupported)?(
                self.instance,
                scanout_id,
                display_width,
                display_height,
                dmabuf_id,
                rect_ptr,
            )
        })
    }

    pub fn present_dmabuf(
        &mut self,
        scanout_id: u32,
        rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        if !self.features.contains(DisplayFeatures::DMABUF_CONSUMER) {
            return Err(DisplayBackendError::MethodNotSupported);
        }

        let rect_ptr = rect.map_or(null(), std::ptr::from_ref);
        into_rust_result!(unsafe {
            self.vtable
                .dmabuf
                .present_dmabuf
                .ok_or(DisplayBackendError::MethodNotSupported)?(
                self.instance,
                scanout_id,
                rect_ptr,
            )
        })
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct DisplayBackend<'userdata> {
    pub features: u64,
    pub create_userdata: *const c_void,
    pub create_userdata_lifetime: PhantomData<&'userdata c_void>,
    pub create_fn: header::krun_display_create_fn,
    pub vtable: DisplayVtable,
}

impl DisplayBackend<'_> {
    /// Create a DisplayBackendInstance, the caller is responsible for only calling this on a
    /// properly constructed DisplayBackend struct.
    pub fn create_instance(&self) -> Result<DisplayBackendInstance, DisplayBackendError> {
        let mut instance = null_mut();
        if let Some(create_fn) = self.create_fn {
            into_rust_result!(unsafe {
                create_fn(&raw mut instance, self.create_userdata, null())
            })?;
        }
        assert!(self.verify());

        let features = DisplayFeatures::from_bits_retain(self.features);

        Ok(DisplayBackendInstance {
            instance,
            vtable: self.vtable,
            features,
        })
    }

    pub fn verify(&self) -> bool {
        let features = DisplayFeatures::from_bits_retain(self.features);

        // Require at least one display feature
        if !features.contains(DisplayFeatures::BASIC_FRAMEBUFFER)
            && !features.contains(DisplayFeatures::DMABUF_CONSUMER)
        {
            error!(
                "This version of libkrun requires BASIC_FRAMEBUFFER or DMABUF_CONSUMER display feature"
            );
            return false;
        }

        for feature in features {
            match feature {
                DisplayFeatures::BASIC_FRAMEBUFFER => {
                    // SAFETY: We have checked the feature flag is enabled, so we should be able to
                    // access the these union fields.
                    if unsafe {
                        self.vtable.basic_framebuffer.disable_scanout.is_none()
                            || self.vtable.basic_framebuffer.configure_scanout.is_none()
                            || self.vtable.basic_framebuffer.alloc_frame.is_none()
                            || self.vtable.basic_framebuffer.present_frame.is_none()
                    } {
                        error!("Missing required methods for BASIC_FRAMEBUFFER");
                        return false;
                    }
                }
                DisplayFeatures::DMABUF_CONSUMER => {
                    // SAFETY: We have checked the feature flag is enabled, so we should be able to
                    // access the these union fields.
                    if unsafe {
                        self.vtable
                            .dmabuf
                            .basic_framebuffer
                            .disable_scanout
                            .is_none()
                            || self.vtable.dmabuf.import_dmabuf.is_none()
                            || self.vtable.dmabuf.unref_dmabuf.is_none()
                            || self.vtable.dmabuf.configure_scanout_dmabuf.is_none()
                            || self.vtable.dmabuf.present_dmabuf.is_none()
                    } {
                        error!("Missing required methods for DMABUF_CONSUMER");
                        return false;
                    }
                }
                features => {
                    warn!("Unknown display features ({features:x}) will be ignored")
                }
            }
        }
        true
    }
}

unsafe impl Send for DisplayBackend<'_> {}

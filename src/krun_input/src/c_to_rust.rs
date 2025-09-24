use crate::{
    ConfigFeatures, EventProviderFeatures, InputAbsInfo, InputBackendError, InputDeviceIds,
    InputEvent, InputEventsImpl, InputQueryConfig, header,
};
use log::{error, warn};
use static_assertions::assert_not_impl_any;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::fd::BorrowedFd;
use std::ptr::{null, null_mut};

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
            -1 => Err(InputBackendError::InternalError),
            -2 => Err(InputBackendError::Again),
            -3 => Err(InputBackendError::MethodNotSupported),
            -4 => Err(InputBackendError::InvalidParam),
            code @ i32::MIN.. => {
                log::warn!("{}: Unknown error result code: {code}", stringify!($expr));
                Err(InputBackendError::InternalError)
            }
        }
    };
}

macro_rules! method_call {
    ($self:ident.$method:ident($($args:expr),*) ) => {
        unsafe {
            $self.vtable.$method
                .ok_or(InputBackendError::MethodNotSupported)?( $self.instance, $($args),* )
        }
    };
}

pub struct InputEventProviderInstance {
    instance: *mut c_void,
    vtable: header::krun_input_event_provider_vtable,
}
impl InputEventsImpl for InputEventProviderInstance {
    /// Get the ready event file descriptor that becomes readable when input events are available
    fn get_read_notify_fd(&self) -> Result<BorrowedFd<'_>, InputBackendError> {
        let fd = method_call! {
            self.get_ready_efd()
        };

        into_rust_result!(fd,
            fd if fd >= 0 => Ok(
                // SAFETY: We have checked the return code of the method, the so the fd should be valid
                //         The lifetime of the fd is the existence of this event provider.
                unsafe { BorrowedFd::borrow_raw(fd) }
            )
        )
    }

    /// Fetch the next available input event, returns None if no events are available
    fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError> {
        let mut event = InputEvent {
            type_: 0,
            code: 0,
            value: 0,
        };

        let result = method_call! {
            self.next_event(&raw mut event)
        };

        into_rust_result!(result,
            1 => Ok(Some(event)),
            0 => Ok(None)
        )
    }
}

pub struct InputConfigInstance {
    instance: *mut c_void,
    vtable: header::krun_input_config_vtable,
}

unsafe impl Send for InputConfigInstance {}
unsafe impl Sync for InputConfigInstance {}

assert_not_impl_any!(InputEventProviderInstance: Sync, Send);

impl Drop for InputEventProviderInstance {
    fn drop(&mut self) {
        let Some(destroy_fn) = self.vtable.destroy else {
            return;
        };

        if let Err(e) = into_rust_result!(unsafe { destroy_fn(self.instance) }) {
            error!("Failed to destroy krun input events instance: {e}");
        }
    }
}

impl Drop for InputConfigInstance {
    fn drop(&mut self) {
        let Some(destroy_fn) = self.vtable.destroy else {
            return;
        };

        if let Err(e) = into_rust_result!(unsafe { destroy_fn(self.instance) }) {
            error!("Failed to destroy krun input config instance: {e}");
        }
    }
}

// Remove the old InputConfigImpl methods as they're not needed

impl InputQueryConfig for InputConfigInstance {
    fn query_device_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        let result = method_call! {
            self.query_device_name(name_buf.as_mut_ptr(), name_buf.len())
        };

        into_rust_result!(result,
            len if len >= 0 => Ok(len as u8)
        )
    }

    fn query_serial_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        let result = method_call! {
            self.query_serial_name(name_buf.as_mut_ptr(), name_buf.len())
        };

        into_rust_result!(result,
            len if len >= 0 => Ok(len as u8)
        )
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
        let result = method_call! {
            self.query_device_ids(ids as *mut InputDeviceIds)
        };

        into_rust_result!(result)
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap_buf: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        let result = method_call! {
            self.query_event_capabilities(event_type, bitmap_buf.as_mut_ptr(), bitmap_buf.len())
        };

        into_rust_result!(result,
            len if len >= 0 => Ok(len as u8)
        )
    }

    fn query_abs_info(
        &self,
        abs_axis: u8,
        abs_info: &mut InputAbsInfo,
    ) -> Result<(), InputBackendError> {
        let result = method_call! {
            self.query_abs_info(abs_axis, abs_info as *mut InputAbsInfo)
        };

        into_rust_result!(result)
    }

    fn query_properties(&self, properties: &mut [u8]) -> Result<u8, InputBackendError> {
        let result = method_call! {
            self.query_properties(properties.as_mut_ptr(), properties.len())
        };

        into_rust_result!(result,
            len if len >= 0 => Ok(len as u8)
        )
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct InputConfigBackend<'userdata> {
    pub features: u64,
    pub create_userdata: *const c_void,
    pub create_userdata_lifetime: PhantomData<&'userdata c_void>,
    pub create_fn: header::krun_input_create_fn,
    pub vtable: header::krun_input_config_vtable,
}
unsafe impl<'a> Send for InputConfigBackend<'a> {}
unsafe impl<'a> Sync for InputConfigBackend<'a> {}

impl<'a> InputConfigBackend<'a> {
    /// Create an InputConfigInstance for handling device configuration
    pub fn create_instance(&self) -> Result<InputConfigInstance, InputBackendError> {
        let mut instance = null_mut();
        if let Some(create_fn) = self.create_fn {
            into_rust_result!(unsafe {
                create_fn(&raw mut instance, self.create_userdata, null())
            })?;
        }
        assert!(self.verify());

        Ok(InputConfigInstance {
            instance,
            vtable: self.vtable,
        })
    }

    pub fn verify(&self) -> bool {
        let features = ConfigFeatures::from_bits_retain(self.features);

        // This requirement might change in the future when we add support for alternatives to this
        if !features.contains(ConfigFeatures::QUERY) {
            error!("This version of libkrun requires QUEUE feature");
            return false;
        }

        for feature in features {
            if feature.contains(ConfigFeatures::QUERY) {
                if self.vtable.query_device_name.is_none()
                    || self.vtable.query_serial_name.is_none()
                    || self.vtable.query_device_ids.is_none()
                    || self.vtable.query_event_capabilities.is_none()
                    || self.vtable.query_abs_info.is_none()
                    || self.vtable.query_properties.is_none()
                {
                    error!("Missing required methods for QUERY feature");
                    return false;
                }
            } else {
                warn!("Unknown features ({feature:x}) will be ignored")
            }
        }
        true
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct InputEventProviderBackend<'userdata> {
    pub features: u64,
    pub create_userdata: *const c_void,
    pub create_userdata_lifetime: PhantomData<&'userdata c_void>,
    pub create_fn: header::krun_input_create_fn,
    pub vtable: header::krun_input_event_provider_vtable,
}

unsafe impl<'a> Send for InputEventProviderBackend<'a> {}
unsafe impl<'a> Sync for InputEventProviderBackend<'a> {}

impl<'a> InputEventProviderBackend<'a> {
    /// Create an InputEventsInstance for handling input events
    pub fn create_instance(&self) -> Result<InputEventProviderInstance, InputBackendError> {
        let mut instance = null_mut();
        if let Some(create_fn) = self.create_fn {
            into_rust_result!(unsafe {
                create_fn(&raw mut instance, self.create_userdata, null())
            })?;
        }
        assert!(self.verify());

        Ok(InputEventProviderInstance {
            instance,
            vtable: self.vtable,
        })
    }

    pub fn verify(&self) -> bool {
        let features = EventProviderFeatures::from_bits_retain(self.features);

        // This requirement might change in the future when we add support for alternatives to this
        if !features.contains(EventProviderFeatures::QUEUE) {
            error!("This version of libkrun requires QUEUE feature");
            return false;
        }

        for feature in features {
            if feature.contains(EventProviderFeatures::QUEUE) {
                if self.vtable.get_ready_efd.is_none() || self.vtable.get_ready_efd.is_none() {
                    error!("Missing required methods for BASIC_FRAMEBUFFER");
                    return false;
                }
            } else {
                warn!("Unknown features ({feature:x}) will be ignored")
            }
        }
        true
    }
}

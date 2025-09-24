use crate::header::{
    KRUN_INPUT_CONFIG_FEATURE_QUERY, KRUN_INPUT_EVENT_PROVIDER_FEATURE_QUEUE,
    krun_input_config_vtable, krun_input_event_provider_vtable,
};
use crate::{
    InputAbsInfo, InputBackendError, InputConfigBackend, InputDeviceIds, InputEvent,
    InputEventProviderBackend,
};
use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr;
use std::ptr::null;

pub trait ObjectNew<T: Sync> {
    fn new(userdata: Option<&T>) -> Self;
}

pub trait InputQueryConfig {
    /// Query device name into provided buffer
    fn query_device_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError>;

    /// Query device name into provided buffer
    fn query_serial_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError>;

    /// Query device IDs into provided structure  
    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError>;

    /// Query event capabilities bitmap for specific event type into provided buffer
    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap_buf: &mut [u8],
    ) -> Result<u8, InputBackendError>;

    /// Query absolute axis information into provided structure
    fn query_abs_info(
        &self,
        abs_axis: u8,
        abs_info: &mut InputAbsInfo,
    ) -> Result<(), InputBackendError>;

    /// Query device properties into provided u32
    fn query_properties(&self, properties: &mut [u8]) -> Result<u8, InputBackendError>;
}

pub trait InputEventsImpl {
    /// Get the file descriptor that becomes ready when input events are available
    fn get_read_notify_fd(&self) -> Result<BorrowedFd<'_>, InputBackendError>;

    /// Fetch the next available input event, returns None if no events are available
    fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError>;
}

pub trait IntoInputConfig<T: Sync> {
    fn into_input_config(userdata: Option<&T>) -> InputConfigBackend<'_>;
}

impl<I, UserData: Send + Sync> IntoInputConfig<UserData> for I
where
    I: InputQueryConfig + ObjectNew<UserData>,
{
    fn into_input_config(userdata: Option<&UserData>) -> InputConfigBackend<'_> {
        extern "C" fn create_config_fn<T: Sync, I: InputQueryConfig + ObjectNew<T>>(
            instance: *mut *mut c_void,
            userdata: *const c_void,
            _reserved: *const c_void,
        ) -> i32 {
            let actual_userdata = if userdata.is_null() {
                None
            } else {
                Some(unsafe { &*(userdata as *const T) })
            };

            let config_obj = I::new(actual_userdata);
            let boxed_config = Box::into_raw(Box::new(config_obj));
            unsafe { *instance = boxed_config as *mut c_void };
            0
        }

        extern "C" fn config_destroy_fn<I>(instance: *mut c_void) -> i32 {
            if instance.is_null() {
                return 0;
            }
            let _ = unsafe { Box::from_raw(instance as *mut I) };
            0
        }

        extern "C" fn query_device_name_fn<T: Sync, I: InputQueryConfig + ObjectNew<T>>(
            instance: *mut c_void,
            name_buf: *mut u8,
            name_buf_len: usize,
        ) -> i32 {
            let config_obj = unsafe { &*(instance as *const I) };
            let name_buf_slice = unsafe { std::slice::from_raw_parts_mut(name_buf, name_buf_len) };

            match config_obj.query_device_name(name_buf_slice) {
                Ok(len) => len as i32,
                Err(e) => e as i32,
            }
        }

        extern "C" fn query_serial_name_fn<T: Sync, I: InputQueryConfig + ObjectNew<T>>(
            instance: *mut c_void,
            name_buf: *mut u8,
            name_buf_len: usize,
        ) -> i32 {
            let config_obj = unsafe { &*(instance as *const I) };
            let name_buf_slice = unsafe { std::slice::from_raw_parts_mut(name_buf, name_buf_len) };

            match config_obj.query_serial_name(name_buf_slice) {
                Ok(len) => len as i32,
                Err(e) => e as i32,
            }
        }

        extern "C" fn query_device_ids_fn<T: Sync, I: InputQueryConfig + ObjectNew<T>>(
            instance: *mut c_void,
            ids: *mut InputDeviceIds,
        ) -> i32 {
            let config_obj = unsafe { &*(instance as *const I) };
            let ids = unsafe { &mut *ids };

            match config_obj.query_device_ids(ids) {
                Ok(()) => 0,
                Err(e) => e as i32,
            }
        }

        extern "C" fn query_event_capabilities_fn<T: Sync, I: InputQueryConfig + ObjectNew<T>>(
            instance: *mut c_void,
            event_type: u8,
            bitmap_buf: *mut u8,
            bitmap_buf_len: usize,
        ) -> i32 {
            let config_obj = unsafe { &*(instance as *const I) };
            let bitmap_buf_slice =
                unsafe { std::slice::from_raw_parts_mut(bitmap_buf, bitmap_buf_len) };

            match config_obj.query_event_capabilities(event_type, bitmap_buf_slice) {
                Ok(len) => len as i32,
                Err(e) => e as i32,
            }
        }

        extern "C" fn query_abs_info_fn<T: Sync, I: InputQueryConfig + ObjectNew<T>>(
            instance: *mut c_void,
            abs_axis: u8,
            abs_info: *mut InputAbsInfo,
        ) -> i32 {
            let config_obj = unsafe { &*(instance as *const I) };
            let abs_info = unsafe { &mut *abs_info };

            match config_obj.query_abs_info(abs_axis, abs_info) {
                Ok(()) => 0,
                Err(e) => e as i32,
            }
        }

        extern "C" fn query_properties_fn<T: Sync, I: InputQueryConfig + ObjectNew<T>>(
            instance: *mut c_void,
            bitmap_buf: *mut u8,
            bitmap_buf_len: usize,
        ) -> i32 {
            let config_obj = unsafe { &*(instance as *const I) };
            let bitmap_buf_slice =
                unsafe { std::slice::from_raw_parts_mut(bitmap_buf, bitmap_buf_len) };

            match config_obj.query_properties(bitmap_buf_slice) {
                Ok(len) => len as i32,
                Err(e) => e as i32,
            }
        }

        let x = userdata.map_or(null(), |t| ptr::from_ref(t) as *const c_void);

        InputConfigBackend {
            features: KRUN_INPUT_CONFIG_FEATURE_QUERY as u64,
            create_userdata: x,
            create_userdata_lifetime: PhantomData,
            create_fn: Some(create_config_fn::<UserData, I>),
            vtable: krun_input_config_vtable {
                destroy: Some(config_destroy_fn::<I>),
                query_device_name: Some(query_device_name_fn::<UserData, I>),
                query_serial_name: Some(query_serial_name_fn::<UserData, I>),
                query_device_ids: Some(query_device_ids_fn::<UserData, I>),
                query_event_capabilities: Some(query_event_capabilities_fn::<UserData, I>),
                query_abs_info: Some(query_abs_info_fn::<UserData, I>),
                query_properties: Some(query_properties_fn::<UserData, I>),
            },
        }
    }
}

pub trait IntoInputEvents<T: Sync> {
    fn into_input_events(userdata: Option<&T>) -> InputEventProviderBackend<'_>;
}

impl<I, UserData: Send + Sync> IntoInputEvents<UserData> for I
where
    I: InputEventsImpl + ObjectNew<UserData>,
{
    fn into_input_events(userdata: Option<&UserData>) -> InputEventProviderBackend<'_> {
        extern "C" fn create_events_fn<T: Sync, I: InputEventsImpl + ObjectNew<T>>(
            instance: *mut *mut c_void,
            userdata: *const c_void,
            _reserved: *const c_void,
        ) -> i32 {
            let actual_userdata = if userdata.is_null() {
                None
            } else {
                Some(unsafe { &*(userdata as *const T) })
            };

            let events_obj = I::new(actual_userdata);
            let boxed_events = Box::into_raw(Box::new(events_obj));
            unsafe { *instance = boxed_events as *mut c_void };
            0
        }

        extern "C" fn events_destroy_fn<I>(instance: *mut c_void) -> i32 {
            if instance.is_null() {
                return 0;
            }
            let _ = unsafe { Box::from_raw(instance as *mut I) };
            0
        }

        extern "C" fn get_ready_efd_fn<I: InputEventsImpl>(instance: *mut c_void) -> i32 {
            let events_obj = unsafe { &*(instance as *const I) };
            match events_obj.get_read_notify_fd() {
                Ok(fd) => fd.as_raw_fd(),
                Err(e) => e as i32,
            }
        }

        extern "C" fn next_event_fn<I: InputEventsImpl>(
            instance: *mut c_void,
            out_event: *mut crate::InputEvent,
        ) -> i32 {
            let events_obj = unsafe { &mut *(instance as *mut I) };
            let out_event = unsafe { &mut *out_event };

            match events_obj.next_event() {
                Ok(Some(event)) => {
                    *out_event = event;
                    1
                }
                Ok(None) => 0,
                Err(e) => e as i32,
            }
        }
        let x: *const c_void = userdata.map_or(null(), |t| ptr::from_ref(t) as *const c_void);
        InputEventProviderBackend {
            features: KRUN_INPUT_EVENT_PROVIDER_FEATURE_QUEUE as u64,
            create_userdata: x,
            create_userdata_lifetime: PhantomData,
            create_fn: Some(create_events_fn::<UserData, I>),
            vtable: krun_input_event_provider_vtable {
                destroy: Some(events_destroy_fn::<I>),
                get_ready_efd: Some(get_ready_efd_fn::<I>),
                next_event: Some(next_event_fn::<I>),
            },
        }
    }
}

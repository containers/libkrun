// Auto-generated. Regenerate with:
//   cargo run -p libkrun-cdylib --bin gen-libkrun-rust-client > src/libkrun-via-cdylib/src/generated.rs

#[allow(unused_imports)]
use std::os::unix::io::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// Marker trait for types exported as opaque C handles.
pub trait FfiHandle {
    const C_HANDLE_NAME: &'static str;
    const TYPE_TAG: u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void;
}

/// Maps Rust types to C-compatible representations.
pub trait FfiType {
    type CRepr;
    const C_TYPE_NAME: &'static str;
    const IS_HANDLE: bool = false;
    fn into_c(self) -> Self::CRepr;
    fn from_c(repr: Self::CRepr) -> Self;
}

macro_rules! impl_ffi_identity {
    ($($t:ty => $n:expr),* $(,)?) => { $(
        impl FfiType for $t {
            type CRepr = $t; const C_TYPE_NAME: &'static str = $n; const IS_HANDLE: bool = false;
            fn into_c(self) -> Self { self } fn from_c(r: Self) -> Self { r }
        }
    )* };
}
impl_ffi_identity! {
    i8 => "int8_t", i16 => "int16_t", i32 => "int32_t", i64 => "int64_t",
    u8 => "uint8_t", u16 => "uint16_t", u32 => "uint32_t", u64 => "uint64_t",
    isize => "ssize_t", usize => "size_t", bool => "bool",
}

impl FfiType for &str {
    type CRepr = ffier::FfierBytes; const C_TYPE_NAME: &'static str = "FfierStr"; const IS_HANDLE: bool = false;
    fn into_c(self) -> ffier::FfierBytes { unsafe { ffier::FfierBytes::from_str(self) } }
    fn from_c(repr: ffier::FfierBytes) -> Self { unsafe { let b = core::slice::from_raw_parts(repr.data, repr.len); core::str::from_utf8_unchecked(b) } }
}

impl FfiType for &[u8] {
    type CRepr = ffier::FfierBytes; const C_TYPE_NAME: &'static str = "FfierBytes"; const IS_HANDLE: bool = false;
    fn into_c(self) -> ffier::FfierBytes { unsafe { ffier::FfierBytes::from_bytes(self) } }
    fn from_c(repr: ffier::FfierBytes) -> Self { unsafe { if repr.data.is_null() { &[] } else { core::slice::from_raw_parts(repr.data, repr.len) } } }
}

impl FfiType for OwnedFd {
    type CRepr = RawFd; const C_TYPE_NAME: &'static str = "int"; const IS_HANDLE: bool = false;
    fn into_c(self) -> RawFd { use std::os::unix::io::IntoRawFd; self.into_raw_fd() as RawFd }
    fn from_c(fd: RawFd) -> Self { unsafe { OwnedFd::from_raw_fd(fd as _) } }
}

impl<'a> FfiType for BorrowedFd<'a> {
    type CRepr = RawFd; const C_TYPE_NAME: &'static str = "int"; const IS_HANDLE: bool = false;
    fn into_c(self) -> RawFd { self.as_raw_fd() as RawFd }
    fn from_c(fd: RawFd) -> Self { unsafe { BorrowedFd::borrow_raw(fd as _) } }
}

impl<T: FfiHandle + 'static> FfiType for &T {
    type CRepr = *mut core::ffi::c_void; const C_TYPE_NAME: &'static str = T::C_HANDLE_NAME; const IS_HANDLE: bool = true;
    fn into_c(self) -> *mut core::ffi::c_void { unsafe { self.as_handle() } }
    fn from_c(_: *mut core::ffi::c_void) -> Self { unimplemented!("client-side &T from_c") }
}
impl<T: FfiHandle + 'static> FfiType for &mut T {
    type CRepr = *mut core::ffi::c_void; const C_TYPE_NAME: &'static str = T::C_HANDLE_NAME; const IS_HANDLE: bool = true;
    fn into_c(self) -> *mut core::ffi::c_void { unsafe { self.as_handle() } }
    fn from_c(_: *mut core::ffi::c_void) -> Self { unimplemented!("client-side &mut T from_c") }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogLevel {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl FfiType for LogLevel {
    type CRepr = u32;
    const C_TYPE_NAME: &'static str = "LogLevel";
    fn into_c(self) -> u32 { self as u32 }
    fn from_c(repr: u32) -> Self { unsafe { core::mem::transmute(repr) } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogStyle {
    Auto = 0,
    Always = 1,
    Never = 2,
}

impl FfiType for LogStyle {
    type CRepr = u32;
    const C_TYPE_NAME: &'static str = "LogStyle";
    fn into_c(self) -> u32 { self as u32 }
    fn from_c(repr: u32) -> Self { unsafe { core::mem::transmute(repr) } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogTarget {
    Default = 0,
    Stdout = 1,
    Stderr = 2,
}

impl FfiType for LogTarget {
    type CRepr = u32;
    const C_TYPE_NAME: &'static str = "LogTarget";
    fn into_c(self) -> u32 { self as u32 }
    fn from_c(repr: u32) -> Self { unsafe { core::mem::transmute(repr) } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidParam,
    DuplicateDevice,
    DeviceLimitExceeded,
    MissingConfig,
    ConflictingConfig,
    OutOfRange,
    FileNotFound,
    PermissionDenied,
    ResourceAlloc,
    BadFd,
    BackendUnavailable,
    FeatureDisabled,
    DiskFormatError,
    AlreadyStarted,
    ValidationFailed,
    HypervisorError,
    BootError,
    Internal,
}

impl Error {
    pub fn from_ffi(r: ffier::FfierResult) -> Self {
        let code = ffier::ffier_result_code(r);
        match code {
            100u32 => Self::InvalidParam,
            101u32 => Self::DuplicateDevice,
            102u32 => Self::DeviceLimitExceeded,
            103u32 => Self::MissingConfig,
            104u32 => Self::ConflictingConfig,
            105u32 => Self::OutOfRange,
            200u32 => Self::FileNotFound,
            201u32 => Self::PermissionDenied,
            202u32 => Self::ResourceAlloc,
            203u32 => Self::BadFd,
            300u32 => Self::BackendUnavailable,
            301u32 => Self::FeatureDisabled,
            302u32 => Self::DiskFormatError,
            400u32 => Self::AlreadyStarted,
            401u32 => Self::ValidationFailed,
            402u32 => Self::HypervisorError,
            403u32 => Self::BootError,
            900u32 => Self::Internal,
            other => panic!("unknown {} error code {}", "Error", other),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParam => write!(f, "InvalidParam"),
            Self::DuplicateDevice => write!(f, "DuplicateDevice"),
            Self::DeviceLimitExceeded => write!(f, "DeviceLimitExceeded"),
            Self::MissingConfig => write!(f, "MissingConfig"),
            Self::ConflictingConfig => write!(f, "ConflictingConfig"),
            Self::OutOfRange => write!(f, "OutOfRange"),
            Self::FileNotFound => write!(f, "FileNotFound"),
            Self::PermissionDenied => write!(f, "PermissionDenied"),
            Self::ResourceAlloc => write!(f, "ResourceAlloc"),
            Self::BadFd => write!(f, "BadFd"),
            Self::BackendUnavailable => write!(f, "BackendUnavailable"),
            Self::FeatureDisabled => write!(f, "feature not enabled in this build"),
            Self::DiskFormatError => write!(f, "DiskFormatError"),
            Self::AlreadyStarted => write!(f, "AlreadyStarted"),
            Self::ValidationFailed => write!(f, "ValidationFailed"),
            Self::HypervisorError => write!(f, "HypervisorError"),
            Self::BootError => write!(f, "BootError"),
            Self::Internal => write!(f, "Internal"),
        }
    }
}

impl std::error::Error for Error {}

unsafe extern "C" {
    pub fn krun_mmio_device_manager_destroy(handle: *mut core::ffi::c_void);
    pub fn krun_mmio_device_manager_new() -> <MmioDeviceManager<'static> as FfiType>::CRepr;
    pub fn krun_mmio_device_manager_add(handle: *mut core::ffi::c_void, device: *mut core::ffi::c_void);
}

pub struct MmioDeviceManager<'a>(*mut core::ffi::c_void, std::marker::PhantomData<&'a ()>);

impl<'a> MmioDeviceManager<'a> {
    #[doc(hidden)]
    pub fn __from_raw(ptr: *mut core::ffi::c_void) -> Self { Self(ptr, std::marker::PhantomData) }
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl<'a> FfiHandle for MmioDeviceManager<'a> {
    const C_HANDLE_NAME: &'static str = "MmioDeviceManager";
    const TYPE_TAG: u32 = 2u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void { self.0 }
}

impl<'a> FfiType for MmioDeviceManager<'a> {
    type CRepr = *mut core::ffi::c_void;
    const C_TYPE_NAME: &'static str = "MmioDeviceManager";
    fn into_c(self) -> *mut core::ffi::c_void { self.__into_raw() }
    fn from_c(repr: *mut core::ffi::c_void) -> Self { Self::__from_raw(repr) }
}

impl<'a> std::fmt::Debug for MmioDeviceManager<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MmioDeviceManager").field(&self.0).finish()
    }
}

impl<'a> MmioDeviceManager<'a> {
    #[doc = " Create an empty device manager."]
    pub fn new() -> MmioDeviceManager<'a> {
        let __raw = unsafe { krun_mmio_device_manager_new() };
        <MmioDeviceManager<'a> as FfiType>::from_c(__raw)
    }
    #[doc = " Add a device to this manager."]
    #[doc = ""]
    #[doc = " Devices are attached in the order they are added. The device must"]
    #[doc = " implement [`AttachDevice`] — all built-in device types"]
    #[doc = " (`FsDevice`, `ConsoleDevice`, etc.) implement this trait."]
    pub fn add(&mut self, device: impl AttachDevice<'a>) -> &mut Self {
        unsafe { krun_mmio_device_manager_add(self.0, device.__into_raw_handle()) };
        self
    }
}

impl<'a> Drop for MmioDeviceManager<'a> {
    fn drop(&mut self) {
        unsafe { krun_mmio_device_manager_destroy(self.0) }
    }
}

unsafe extern "C" {
    pub fn krun_fs_device_destroy(handle: *mut core::ffi::c_void);
    pub fn krun_fs_device_new(tag: <&'static str as FfiType>::CRepr, host_path: <&'static str as FfiType>::CRepr, err_out: *mut *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    pub fn krun_fs_device_set_dax_window_size(handle: *mut core::ffi::c_void, bytes: <u64 as FfiType>::CRepr);
}

pub struct FsDevice<'a>(*mut core::ffi::c_void, std::marker::PhantomData<&'a ()>);

impl<'a> FsDevice<'a> {
    #[doc(hidden)]
    pub fn __from_raw(ptr: *mut core::ffi::c_void) -> Self { Self(ptr, std::marker::PhantomData) }
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl<'a> FfiHandle for FsDevice<'a> {
    const C_HANDLE_NAME: &'static str = "FsDevice";
    const TYPE_TAG: u32 = 3u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void { self.0 }
}

impl<'a> FfiType for FsDevice<'a> {
    type CRepr = *mut core::ffi::c_void;
    const C_TYPE_NAME: &'static str = "FsDevice";
    fn into_c(self) -> *mut core::ffi::c_void { self.__into_raw() }
    fn from_c(repr: *mut core::ffi::c_void) -> Self { Self::__from_raw(repr) }
}

impl<'a> std::fmt::Debug for FsDevice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FsDevice").field(&self.0).finish()
    }
}

impl<'a> FsDevice<'a> {
    #[doc = " Create a new virtiofs device."]
    #[doc = ""]
    #[doc = " # Arguments"]
    #[doc = ""]
    #[doc = " - `tag`: the filesystem tag visible to the guest (e.g. `\"/dev/root\"`)."]
    #[doc = " - `host_path`: the host directory to share."]
    pub fn new(tag: &str, host_path: &str) -> Result<FsDevice<'a>, Error> {
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __raw = unsafe { krun_fs_device_new(<&str as FfiType>::into_c(tag), <&str as FfiType>::into_c(host_path), &mut __err as *mut *mut core::ffi::c_void) };
        if !__raw.is_null() {
            Ok(<FsDevice<'a> as FfiType>::from_c(__raw))
        } else {
            let __r = unsafe { krun_error_result(__err) };
            unsafe { krun_error_destroy(__err) };
            Err(Error::from_ffi(__r))
        }
    }
    #[doc = " Set the size of the DAX (direct access) shared memory window."]
    #[doc = ""]
    #[doc = " When set, the guest can memory-map files from the shared filesystem"]
    #[doc = " directly into its address space, avoiding data copies. If not set,"]
    #[doc = " no DAX window is allocated."]
    pub fn set_dax_window_size(&mut self, bytes: u64) {
        unsafe { krun_fs_device_set_dax_window_size(self.0, <u64 as FfiType>::into_c(bytes)) }
    }
}

impl<'a> Drop for FsDevice<'a> {
    fn drop(&mut self) {
        unsafe { krun_fs_device_destroy(self.0) }
    }
}

unsafe extern "C" {
    pub fn krun_console_device_destroy(handle: *mut core::ffi::c_void);
    pub fn krun_console_device_builder() -> <ConsoleBuilder<'static> as FfiType>::CRepr;
}

pub struct ConsoleDevice<'a>(*mut core::ffi::c_void, std::marker::PhantomData<&'a ()>);

impl<'a> ConsoleDevice<'a> {
    #[doc(hidden)]
    pub fn __from_raw(ptr: *mut core::ffi::c_void) -> Self { Self(ptr, std::marker::PhantomData) }
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl<'a> FfiHandle for ConsoleDevice<'a> {
    const C_HANDLE_NAME: &'static str = "ConsoleDevice";
    const TYPE_TAG: u32 = 4u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void { self.0 }
}

impl<'a> FfiType for ConsoleDevice<'a> {
    type CRepr = *mut core::ffi::c_void;
    const C_TYPE_NAME: &'static str = "ConsoleDevice";
    fn into_c(self) -> *mut core::ffi::c_void { self.__into_raw() }
    fn from_c(repr: *mut core::ffi::c_void) -> Self { Self::__from_raw(repr) }
}

impl<'a> std::fmt::Debug for ConsoleDevice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ConsoleDevice").field(&self.0).finish()
    }
}

impl<'a> ConsoleDevice<'a> {
    #[doc = " Create a new console builder."]
    pub fn builder() -> ConsoleBuilder<'a> {
        let __raw = unsafe { krun_console_device_builder() };
        <ConsoleBuilder<'a> as FfiType>::from_c(__raw)
    }
}

impl<'a> Drop for ConsoleDevice<'a> {
    fn drop(&mut self) {
        unsafe { krun_console_device_destroy(self.0) }
    }
}

unsafe extern "C" {
    pub fn krun_console_builder_destroy(handle: *mut core::ffi::c_void);
    pub fn krun_console_builder_add_tty_port(handle: *mut core::ffi::c_void, name: <&'static str as FfiType>::CRepr, tty_fd: <BorrowedFd<'static> as FfiType>::CRepr, result: *mut <u32 as FfiType>::CRepr, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
    pub fn krun_console_builder_set_kernel_console(handle: *mut core::ffi::c_void, port_index: <u32 as FfiType>::CRepr, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
    pub fn krun_console_builder_build(handle: *mut core::ffi::c_void, err_out: *mut *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

pub struct ConsoleBuilder<'a>(*mut core::ffi::c_void, std::marker::PhantomData<&'a ()>);

impl<'a> ConsoleBuilder<'a> {
    #[doc(hidden)]
    pub fn __from_raw(ptr: *mut core::ffi::c_void) -> Self { Self(ptr, std::marker::PhantomData) }
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl<'a> FfiHandle for ConsoleBuilder<'a> {
    const C_HANDLE_NAME: &'static str = "ConsoleBuilder";
    const TYPE_TAG: u32 = 5u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void { self.0 }
}

impl<'a> FfiType for ConsoleBuilder<'a> {
    type CRepr = *mut core::ffi::c_void;
    const C_TYPE_NAME: &'static str = "ConsoleBuilder";
    fn into_c(self) -> *mut core::ffi::c_void { self.__into_raw() }
    fn from_c(repr: *mut core::ffi::c_void) -> Self { Self::__from_raw(repr) }
}

impl<'a> std::fmt::Debug for ConsoleBuilder<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ConsoleBuilder").field(&self.0).finish()
    }
}

impl<'a> ConsoleBuilder<'a> {
    #[doc = " Add a TTY-backed port to the console."]
    #[doc = ""]
    #[doc = " If the fd refers to a real terminal, raw mode will be enabled on it"]
    #[doc = " when the VM starts, and restored on shutdown."]
    #[doc = ""]
    #[doc = " # Arguments"]
    #[doc = ""]
    #[doc = " - `name`: the port name visible to the guest (e.g. `\"tty0\"`)."]
    #[doc = " - `tty_fd`: borrowed fd for the host TTY; duplicated internally, caller retains ownership."]
    #[doc = ""]
    #[doc = " # Returns"]
    #[doc = ""]
    #[doc = " The zero-based port index, usable with [`set_kernel_console`](ConsoleBuilder::set_kernel_console)."]
    pub fn add_tty_port(&mut self, name: &str, tty_fd: BorrowedFd<'a>) -> Result<u32, Error> {
        let mut __out = std::mem::MaybeUninit::uninit();
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __r = unsafe { krun_console_builder_add_tty_port(self.0, <&str as FfiType>::into_c(name), <BorrowedFd<'a> as FfiType>::into_c(tty_fd), __out.as_mut_ptr(), &mut __err as *mut *mut core::ffi::c_void) };
        if __r == 0 {
            Ok(<u32 as FfiType>::from_c(unsafe { __out.assume_init() }))
        } else {
            Err(Error::from_ffi(__r))
        }
    }
    #[doc = " Designate a port as the kernel console (`console=hvcN`)."]
    #[doc = ""]
    #[doc = " # Arguments"]
    #[doc = ""]
    #[doc = " - `port_index`: a value returned by [`add_tty_port`](ConsoleBuilder::add_tty_port)."]
    pub fn set_kernel_console(&mut self, port_index: u32) -> Result<(), Error> {
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __r = unsafe { krun_console_builder_set_kernel_console(self.0, <u32 as FfiType>::into_c(port_index), &mut __err as *mut *mut core::ffi::c_void) };
        if __r == 0 { Ok(()) } else { Err(Error::from_ffi(__r)) }
    }
    #[doc = " Build the console device. At least one port must have been added."]
    pub fn build(self, ) -> Result<ConsoleDevice<'a>, Error> {
        let __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __raw = unsafe { krun_console_builder_build(__handle, &mut __err as *mut *mut core::ffi::c_void) };
        if !__raw.is_null() {
            Ok(<ConsoleDevice<'a> as FfiType>::from_c(__raw))
        } else {
            let __r = unsafe { krun_error_result(__err) };
            unsafe { krun_error_destroy(__err) };
            Err(Error::from_ffi(__r))
        }
    }
}

impl<'a> Drop for ConsoleBuilder<'a> {
    fn drop(&mut self) {
        unsafe { krun_console_builder_destroy(self.0) }
    }
}

unsafe extern "C" {
    pub fn krun_balloon_device_destroy(handle: *mut core::ffi::c_void);
    pub fn krun_balloon_device_new(err_out: *mut *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

pub struct BalloonDevice(*mut core::ffi::c_void);

impl BalloonDevice {
    #[doc(hidden)]
    pub fn __from_raw(ptr: *mut core::ffi::c_void) -> Self { Self(ptr) }
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl FfiHandle for BalloonDevice {
    const C_HANDLE_NAME: &'static str = "BalloonDevice";
    const TYPE_TAG: u32 = 6u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void { self.0 }
}

impl FfiType for BalloonDevice {
    type CRepr = *mut core::ffi::c_void;
    const C_TYPE_NAME: &'static str = "BalloonDevice";
    fn into_c(self) -> *mut core::ffi::c_void { self.__into_raw() }
    fn from_c(repr: *mut core::ffi::c_void) -> Self { Self::__from_raw(repr) }
}

impl std::fmt::Debug for BalloonDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BalloonDevice").field(&self.0).finish()
    }
}

impl BalloonDevice {
    #[doc = " Create a new balloon device."]
    pub fn new() -> Result<BalloonDevice, Error> {
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __raw = unsafe { krun_balloon_device_new(&mut __err as *mut *mut core::ffi::c_void) };
        if !__raw.is_null() {
            Ok(<BalloonDevice as FfiType>::from_c(__raw))
        } else {
            let __r = unsafe { krun_error_result(__err) };
            unsafe { krun_error_destroy(__err) };
            Err(Error::from_ffi(__r))
        }
    }
}

impl Drop for BalloonDevice {
    fn drop(&mut self) {
        unsafe { krun_balloon_device_destroy(self.0) }
    }
}

unsafe extern "C" {
    pub fn krun_rng_device_destroy(handle: *mut core::ffi::c_void);
    pub fn krun_rng_device_new(err_out: *mut *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

pub struct RngDevice(*mut core::ffi::c_void);

impl RngDevice {
    #[doc(hidden)]
    pub fn __from_raw(ptr: *mut core::ffi::c_void) -> Self { Self(ptr) }
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl FfiHandle for RngDevice {
    const C_HANDLE_NAME: &'static str = "RngDevice";
    const TYPE_TAG: u32 = 7u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void { self.0 }
}

impl FfiType for RngDevice {
    type CRepr = *mut core::ffi::c_void;
    const C_TYPE_NAME: &'static str = "RngDevice";
    fn into_c(self) -> *mut core::ffi::c_void { self.__into_raw() }
    fn from_c(repr: *mut core::ffi::c_void) -> Self { Self::__from_raw(repr) }
}

impl std::fmt::Debug for RngDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RngDevice").field(&self.0).finish()
    }
}

impl RngDevice {
    #[doc = " Create a new RNG device."]
    pub fn new() -> Result<RngDevice, Error> {
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __raw = unsafe { krun_rng_device_new(&mut __err as *mut *mut core::ffi::c_void) };
        if !__raw.is_null() {
            Ok(<RngDevice as FfiType>::from_c(__raw))
        } else {
            let __r = unsafe { krun_error_result(__err) };
            unsafe { krun_error_destroy(__err) };
            Err(Error::from_ffi(__r))
        }
    }
}

impl Drop for RngDevice {
    fn drop(&mut self) {
        unsafe { krun_rng_device_destroy(self.0) }
    }
}

unsafe extern "C" {
    pub fn krun_init_destroy(handle: *mut core::ffi::c_void);
    pub fn krun_init_builder(_rootfs: <&'static FsDevice<'static> as FfiType>::CRepr, console: <&'static mut ConsoleBuilder<'static> as FfiType>::CRepr) -> <InitBuilder<'static, 'static> as FfiType>::CRepr;
}

pub struct Init(*mut core::ffi::c_void);

impl Init {
    #[doc(hidden)]
    pub fn __from_raw(ptr: *mut core::ffi::c_void) -> Self { Self(ptr) }
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl FfiHandle for Init {
    const C_HANDLE_NAME: &'static str = "Init";
    const TYPE_TAG: u32 = 8u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void { self.0 }
}

impl FfiType for Init {
    type CRepr = *mut core::ffi::c_void;
    const C_TYPE_NAME: &'static str = "Init";
    fn into_c(self) -> *mut core::ffi::c_void { self.__into_raw() }
    fn from_c(repr: *mut core::ffi::c_void) -> Self { Self::__from_raw(repr) }
}

impl std::fmt::Debug for Init {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Init").field(&self.0).finish()
    }
}

impl Init {
    #[doc = " Create a new init payload builder."]
    #[doc = ""]
    #[doc = " # Arguments"]
    #[doc = ""]
    #[doc = " - `_rootfs`: the root filesystem device (reserved for future validation)."]
    #[doc = " - `console`: console builder; an output-only port for boot messages is added automatically."]
    pub fn builder<'a, 'b>(_rootfs: &FsDevice<'_>, console: &'b mut ConsoleBuilder<'a>) -> InitBuilder<'a, 'b> {
        let __raw = unsafe { krun_init_builder(FfiHandle::as_handle(_rootfs), FfiHandle::as_handle(console)) };
        <InitBuilder<'a, 'b> as FfiType>::from_c(__raw)
    }
}

impl Drop for Init {
    fn drop(&mut self) {
        unsafe { krun_init_destroy(self.0) }
    }
}

unsafe extern "C" {
    pub fn krun_init_builder_destroy(handle: *mut core::ffi::c_void);
    pub fn krun_init_builder_console_auto(handle: *mut core::ffi::c_void, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
    pub fn krun_init_builder_console_tty(handle: *mut core::ffi::c_void, tty_fd: <BorrowedFd<'static> as FfiType>::CRepr, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
    pub fn krun_init_builder_console_redirects(handle: *mut core::ffi::c_void, stdin_fd: <i32 as FfiType>::CRepr, stdout_fd: <i32 as FfiType>::CRepr, stderr_fd: <i32 as FfiType>::CRepr, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
    pub fn krun_init_builder_exec(handle: *mut core::ffi::c_void, exec_path: <&'static str as FfiType>::CRepr, args: *const ffier::FfierBytes, args_len: usize, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
    pub fn krun_init_builder_env(handle: *mut core::ffi::c_void, env: *const ffier::FfierBytes, env_len: usize, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
    pub fn krun_init_builder_workdir(handle: *mut core::ffi::c_void, path: <&'static str as FfiType>::CRepr, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
    pub fn krun_init_builder_build(handle: *mut core::ffi::c_void, err_out: *mut *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

pub struct InitBuilder<'a, 'b>(*mut core::ffi::c_void, std::marker::PhantomData<(&'a (), &'b ())>);

impl<'a, 'b> InitBuilder<'a, 'b> {
    #[doc(hidden)]
    pub fn __from_raw(ptr: *mut core::ffi::c_void) -> Self { Self(ptr, std::marker::PhantomData) }
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl<'a, 'b> FfiHandle for InitBuilder<'a, 'b> {
    const C_HANDLE_NAME: &'static str = "InitBuilder";
    const TYPE_TAG: u32 = 9u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void { self.0 }
}

impl<'a, 'b> FfiType for InitBuilder<'a, 'b> {
    type CRepr = *mut core::ffi::c_void;
    const C_TYPE_NAME: &'static str = "InitBuilder";
    fn into_c(self) -> *mut core::ffi::c_void { self.__into_raw() }
    fn from_c(repr: *mut core::ffi::c_void) -> Self { Self::__from_raw(repr) }
}

impl<'a, 'b> std::fmt::Debug for InitBuilder<'a, 'b> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("InitBuilder").field(&self.0).finish()
    }
}

impl<'a, 'b> InitBuilder<'a, 'b> {
    #[doc = " Auto-detect console setup."]
    #[doc = ""]
    #[doc = " Tries /dev/tty (the controlling terminal) first. If available, creates"]
    #[doc = " a single TTY port for payload I/O. Otherwise falls back to separate"]
    #[doc = " krun-payload-stdin/stdout/stderr redirect ports on the stdio fds."]
    pub fn console_auto(self, ) -> Result<Self, Error> {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __r = unsafe { krun_init_builder_console_auto(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, &mut __err as *mut *mut core::ffi::c_void) };
        if __r == 0 { Ok(Self(__handle, std::marker::PhantomData)) } else { Err(Error::from_ffi(__r)) }
    }
    #[doc = " Set up a single TTY port for payload I/O."]
    #[doc = ""]
    #[doc = " The payload's stdin/stdout/stderr will all be connected to this"]
    #[doc = " terminal. Raw mode is enabled automatically if `tty_fd` is a"]
    #[doc = " real terminal."]
    pub fn console_tty(self, tty_fd: BorrowedFd<'a>) -> Result<Self, Error> {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __r = unsafe { krun_init_builder_console_tty(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, <BorrowedFd<'a> as FfiType>::into_c(tty_fd), &mut __err as *mut *mut core::ffi::c_void) };
        if __r == 0 { Ok(Self(__handle, std::marker::PhantomData)) } else { Err(Error::from_ffi(__r)) }
    }
    #[doc = " Set up separate redirect ports for payload stdin, stdout, and stderr."]
    #[doc = ""]
    #[doc = " Each fd is duplicated internally. Pass `-1` (or any negative value)"]
    #[doc = " to skip a particular stream."]
    pub fn console_redirects(self, stdin_fd: i32, stdout_fd: i32, stderr_fd: i32) -> Result<Self, Error> {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __r = unsafe { krun_init_builder_console_redirects(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, <i32 as FfiType>::into_c(stdin_fd), <i32 as FfiType>::into_c(stdout_fd), <i32 as FfiType>::into_c(stderr_fd), &mut __err as *mut *mut core::ffi::c_void) };
        if __r == 0 { Ok(Self(__handle, std::marker::PhantomData)) } else { Err(Error::from_ffi(__r)) }
    }
    #[doc = " Set the command to execute inside the guest."]
    #[doc = ""]
    #[doc = " # Arguments"]
    #[doc = ""]
    #[doc = " - `exec_path`: absolute path to the executable within the guest rootfs."]
    #[doc = " - `args`: command-line arguments (not including argv\\[0\\])."]
    pub fn exec(self, exec_path: &str, args: &[&str]) -> Result<Self, Error> {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let __ffi_args: Vec<ffier::FfierBytes> = args.iter().map(|s| unsafe { ffier::FfierBytes::from_str(s) }).collect();
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __r = unsafe { krun_init_builder_exec(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, <&str as FfiType>::into_c(exec_path), __ffi_args.as_ptr(), __ffi_args.len(), &mut __err as *mut *mut core::ffi::c_void) };
        if __r == 0 { Ok(Self(__handle, std::marker::PhantomData)) } else { Err(Error::from_ffi(__r)) }
    }
    #[doc = " Set environment variables for the guest process."]
    #[doc = ""]
    #[doc = " # Arguments"]
    #[doc = ""]
    #[doc = " - `env`: each string should be in `KEY=VALUE` format."]
    pub fn env(self, env: &[&str]) -> Result<Self, Error> {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let __ffi_env: Vec<ffier::FfierBytes> = env.iter().map(|s| unsafe { ffier::FfierBytes::from_str(s) }).collect();
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __r = unsafe { krun_init_builder_env(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, __ffi_env.as_ptr(), __ffi_env.len(), &mut __err as *mut *mut core::ffi::c_void) };
        if __r == 0 { Ok(Self(__handle, std::marker::PhantomData)) } else { Err(Error::from_ffi(__r)) }
    }
    #[doc = " Set the working directory for the guest process."]
    #[doc = ""]
    #[doc = " # Arguments"]
    #[doc = ""]
    #[doc = " - `path`: absolute path within the guest rootfs."]
    pub fn workdir(self, path: &str) -> Result<Self, Error> {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __r = unsafe { krun_init_builder_workdir(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, <&str as FfiType>::into_c(path), &mut __err as *mut *mut core::ffi::c_void) };
        if __r == 0 { Ok(Self(__handle, std::marker::PhantomData)) } else { Err(Error::from_ffi(__r)) }
    }
    #[doc = " Build the init payload."]
    #[doc = ""]
    #[doc = " Requires [`exec`](InitBuilder::exec) to have been called. If no"]
    #[doc = " console was explicitly configured (via [`console_tty`](InitBuilder::console_tty)"]
    #[doc = " or [`console_redirects`](InitBuilder::console_redirects)), auto-detection"]
    #[doc = " is used: `/dev/tty` if available, otherwise stdin/stdout/stderr."]
    pub fn build(self, ) -> Result<Init, Error> {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __raw = unsafe { krun_init_builder_build(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, &mut __err as *mut *mut core::ffi::c_void) };
        if !__raw.is_null() {
            Ok(<Init as FfiType>::from_c(__raw))
        } else {
            let __r = unsafe { krun_error_result(__err) };
            unsafe { krun_error_destroy(__err) };
            Err(Error::from_ffi(__r))
        }
    }
}

impl<'a, 'b> Drop for InitBuilder<'a, 'b> {
    fn drop(&mut self) {
        unsafe { krun_init_builder_destroy(self.0) }
    }
}

unsafe extern "C" {
    pub fn krun_vmm_builder_destroy(handle: *mut core::ffi::c_void);
    pub fn krun_vmm_builder_new() -> <VmmBuilder<'static> as FfiType>::CRepr;
    pub fn krun_vmm_builder_vcpus(handle: *mut core::ffi::c_void, count: <u8 as FfiType>::CRepr, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
    pub fn krun_vmm_builder_ram_mib(handle: *mut core::ffi::c_void, mib: <u32 as FfiType>::CRepr, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
    pub fn krun_vmm_builder_payload(handle: *mut core::ffi::c_void, payload: *mut core::ffi::c_void);
    pub fn krun_vmm_builder_devices(handle: *mut core::ffi::c_void, devices: <MmioDeviceManager<'static> as FfiType>::CRepr);
    pub fn krun_vmm_builder_build(handle: *mut core::ffi::c_void, err_out: *mut *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

pub struct VmmBuilder<'a>(*mut core::ffi::c_void, std::marker::PhantomData<&'a ()>);

impl<'a> VmmBuilder<'a> {
    #[doc(hidden)]
    pub fn __from_raw(ptr: *mut core::ffi::c_void) -> Self { Self(ptr, std::marker::PhantomData) }
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl<'a> FfiHandle for VmmBuilder<'a> {
    const C_HANDLE_NAME: &'static str = "VmmBuilder";
    const TYPE_TAG: u32 = 10u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void { self.0 }
}

impl<'a> FfiType for VmmBuilder<'a> {
    type CRepr = *mut core::ffi::c_void;
    const C_TYPE_NAME: &'static str = "VmmBuilder";
    fn into_c(self) -> *mut core::ffi::c_void { self.__into_raw() }
    fn from_c(repr: *mut core::ffi::c_void) -> Self { Self::__from_raw(repr) }
}

impl<'a> std::fmt::Debug for VmmBuilder<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VmmBuilder").field(&self.0).finish()
    }
}

impl<'a> VmmBuilder<'a> {
    #[doc = " Create a new VM builder with no configuration."]
    pub fn new() -> VmmBuilder<'a> {
        let __raw = unsafe { krun_vmm_builder_new() };
        <VmmBuilder<'a> as FfiType>::from_c(__raw)
    }
    #[doc = " Set the number of virtual CPUs. Must be at least 1."]
    pub fn vcpus(self, count: u8) -> Result<Self, Error> {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __r = unsafe { krun_vmm_builder_vcpus(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, <u8 as FfiType>::into_c(count), &mut __err as *mut *mut core::ffi::c_void) };
        if __r == 0 { Ok(Self(__handle, std::marker::PhantomData)) } else { Err(Error::from_ffi(__r)) }
    }
    #[doc = " Set the amount of guest RAM in mebibytes. Must be at least 1."]
    pub fn ram_mib(self, mib: u32) -> Result<Self, Error> {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __r = unsafe { krun_vmm_builder_ram_mib(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, <u32 as FfiType>::into_c(mib), &mut __err as *mut *mut core::ffi::c_void) };
        if __r == 0 { Ok(Self(__handle, std::marker::PhantomData)) } else { Err(Error::from_ffi(__r)) }
    }
    #[doc = " Set the payload to run inside the VM."]
    #[doc = ""]
    #[doc = " Currently the only payload type is `Init`, which runs a process"]
    #[doc = " as PID 1 inside the guest using the built-in krun init."]
    pub fn payload(self, payload: impl Payload) -> Self {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        unsafe { krun_vmm_builder_payload(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, payload.__into_raw_handle()) };
        Self(__handle, std::marker::PhantomData)
    }
    #[doc = " Set the device manager containing all virtio devices."]
    #[doc = ""]
    #[doc = " The device manager determines which transport bus is used (currently"]
    #[doc = " only [`MmioDeviceManager`] for virtio-mmio)."]
    pub fn devices(self, devices: MmioDeviceManager<'a>) -> Self {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        unsafe { krun_vmm_builder_devices(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, <MmioDeviceManager<'a> as FfiType>::into_c(devices)) };
        Self(__handle, std::marker::PhantomData)
    }
    #[doc = " Build the VM, creating guest memory, attaching devices, and starting"]
    #[doc = " vCPUs. All required fields (`vcpus`, `ram_mib`, `payload`, `devices`)"]
    #[doc = " must have been set."]
    pub fn build(self, ) -> Result<Vmm<'a>, Error> {
        let mut __handle = { let this = std::mem::ManuallyDrop::new(self); this.0 };
        let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
        let __raw = unsafe { krun_vmm_builder_build(&mut __handle as *mut *mut core::ffi::c_void as *mut core::ffi::c_void, &mut __err as *mut *mut core::ffi::c_void) };
        if !__raw.is_null() {
            Ok(<Vmm<'a> as FfiType>::from_c(__raw))
        } else {
            let __r = unsafe { krun_error_result(__err) };
            unsafe { krun_error_destroy(__err) };
            Err(Error::from_ffi(__r))
        }
    }
}

impl<'a> Drop for VmmBuilder<'a> {
    fn drop(&mut self) {
        unsafe { krun_vmm_builder_destroy(self.0) }
    }
}

unsafe extern "C" {
    pub fn krun_vmm_destroy(handle: *mut core::ffi::c_void);
    pub fn krun_vmm_run(handle: *mut core::ffi::c_void);
}

pub struct Vmm<'a>(*mut core::ffi::c_void, std::marker::PhantomData<&'a ()>);

impl<'a> Vmm<'a> {
    #[doc(hidden)]
    pub fn __from_raw(ptr: *mut core::ffi::c_void) -> Self { Self(ptr, std::marker::PhantomData) }
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl<'a> FfiHandle for Vmm<'a> {
    const C_HANDLE_NAME: &'static str = "Vmm";
    const TYPE_TAG: u32 = 11u32;
    unsafe fn as_handle(&self) -> *mut core::ffi::c_void { self.0 }
}

impl<'a> FfiType for Vmm<'a> {
    type CRepr = *mut core::ffi::c_void;
    const C_TYPE_NAME: &'static str = "Vmm";
    fn into_c(self) -> *mut core::ffi::c_void { self.__into_raw() }
    fn from_c(repr: *mut core::ffi::c_void) -> Self { Self::__from_raw(repr) }
}

impl<'a> std::fmt::Debug for Vmm<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Vmm").field(&self.0).finish()
    }
}

impl<'a> Vmm<'a> {
    #[doc = " Run the VM event loop. This call blocks until the VM exits or a"]
    #[doc = " fatal error occurs."]
    pub fn run(&mut self, ) {
        unsafe { krun_vmm_run(self.0) }
    }
}

impl<'a> Drop for Vmm<'a> {
    fn drop(&mut self) {
        unsafe { krun_vmm_destroy(self.0) }
    }
}

pub trait PushStr {
    fn push(&mut self, s: &str) -> bool;
    #[doc(hidden)]
    fn __ffier_vtable() -> &'static PushStrVtable where Self: Sized {
        &PushStrVtable {
            drop: Some({
                unsafe extern "C" fn __drop_trampoline<__T>(__ud: *mut core::ffi::c_void) {
                    unsafe { drop(Box::from_raw(__ud as *mut __T)) };
                }
                __drop_trampoline::<Self>
            }),
            push: Some({
                unsafe extern "C" fn __trampoline<__T: PushStr>(
                    __ud: *mut core::ffi::c_void, s: <&'static str as FfiType>::CRepr,
                ) -> <bool as FfiType>::CRepr {
                    let __val = unsafe { &mut *(__ud as *mut __T) };
                    let __result = __val.push(<&str as FfiType>::from_c(s));
                    <bool as FfiType>::into_c(__result)
                }
                __trampoline::<Self>
            }),
        }
    }
    #[doc(hidden)]
    fn __into_raw_handle(self) -> *mut core::ffi::c_void where Self: Sized {
        let __vtable: &'static PushStrVtable = Self::__ffier_vtable();
        let __user_data = Box::into_raw(Box::new(self));
        let vtable_size: u16 = core::mem::size_of::<PushStrVtable>().try_into().expect("vtable_size exceeds u16::MAX");
        ffier::ffier_handle_new_with_metadata(12u32, 0, ffier::VtableHandle {
            vtable_ptr: __vtable as *const PushStrVtable as *const core::ffi::c_void,
            user_data: __user_data as *const core::ffi::c_void,
            vtable_size,
        })
    }
}

#[repr(C)]
pub struct PushStrVtable {
    pub drop: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    pub push: Option<unsafe extern "C" fn(*mut core::ffi::c_void, <&'static str as FfiType>::CRepr) -> <bool as FfiType>::CRepr>,
}

pub struct VtablePushStr(*mut core::ffi::c_void);

impl VtablePushStr {
    #[doc(hidden)]
    pub fn __into_raw(self) -> *mut core::ffi::c_void { let this = std::mem::ManuallyDrop::new(self); this.0 }
}

impl Drop for VtablePushStr {
    fn drop(&mut self) {}
}

unsafe extern "C" {
    pub fn krun_error_code(handle: *mut core::ffi::c_void) -> <u32 as FfiType>::CRepr;
    pub fn krun_error_message(handle: *mut core::ffi::c_void, writer: *mut core::ffi::c_void);
    pub fn krun_error_result(handle: *mut core::ffi::c_void) -> <u64 as FfiType>::CRepr;
    pub fn krun_error_destroy(handle: *mut core::ffi::c_void);
}

pub trait Payload {
    #[doc(hidden)]
    fn __into_raw_handle(self) -> *mut core::ffi::c_void where Self: Sized;
}

unsafe extern "C" {
}

impl Payload for Init {
    fn __into_raw_handle(self) -> *mut core::ffi::c_void {
        let this = std::mem::ManuallyDrop::new(self);
        this.0
    }
}

pub trait AttachDevice<'a> {
    #[doc(hidden)]
    fn __into_raw_handle(self) -> *mut core::ffi::c_void where Self: Sized;
}

unsafe extern "C" {
}

impl<'a> AttachDevice<'a> for FsDevice<'a> {
    fn __into_raw_handle(self) -> *mut core::ffi::c_void {
        let this = std::mem::ManuallyDrop::new(self);
        this.0
    }
}

unsafe extern "C" {
}

impl<'a> AttachDevice<'a> for ConsoleDevice<'a> {
    fn __into_raw_handle(self) -> *mut core::ffi::c_void {
        let this = std::mem::ManuallyDrop::new(self);
        this.0
    }
}

unsafe extern "C" {
}

impl<'a> AttachDevice<'a> for BalloonDevice {
    fn __into_raw_handle(self) -> *mut core::ffi::c_void {
        let this = std::mem::ManuallyDrop::new(self);
        this.0
    }
}

unsafe extern "C" {
}

impl<'a> AttachDevice<'a> for RngDevice {
    fn __into_raw_handle(self) -> *mut core::ffi::c_void {
        let this = std::mem::ManuallyDrop::new(self);
        this.0
    }
}

unsafe extern "C" {
    pub fn krun_init_log(target: <LogTarget as FfiType>::CRepr, level: <LogLevel as FfiType>::CRepr, style: <LogStyle as FfiType>::CRepr, err_out: *mut *mut core::ffi::c_void) -> ffier::FfierResult;
}

pub fn init_log(target: LogTarget, level: LogLevel, style: LogStyle) -> Result<(), Error> {
    let mut __err: *mut core::ffi::c_void = core::ptr::null_mut();
    let __r = unsafe { krun_init_log(<LogTarget as FfiType>::into_c(target), <LogLevel as FfiType>::into_c(level), <LogStyle as FfiType>::into_c(style), &mut __err as *mut *mut core::ffi::c_void) };
    if __r == 0 { Ok(()) } else { Err(Error::from_ffi(__r)) }
}


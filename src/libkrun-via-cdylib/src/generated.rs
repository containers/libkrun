// Auto-generated. Regenerate with:
//   cargo run -p libkrun-cdylib --bin gen-libkrun-rust-client > src/libkrun-via-cdylib/src/generated.rs

#[allow(unused_imports)]
use std::os::unix::io::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Error
{
    InvalidParam, DuplicateDevice, DeviceLimitExceeded, MissingConfig,
    ConflictingConfig, OutOfRange, FileNotFound, PermissionDenied,
    ResourceAlloc, BadFd, BackendUnavailable, FeatureDisabled,
    DiskFormatError, AlreadyStarted, ValidationFailed, HypervisorError,
    BootError, Internal
} impl Error
{
    pub fn from_ffi(mut err : ffier :: FfierError) -> Self
    {
        let code = err.code; unsafe { err.free() }; match code
        {
            100u64 => Self :: InvalidParam, 101u64 => Self :: DuplicateDevice,
            102u64 => Self :: DeviceLimitExceeded, 103u64 => Self ::
            MissingConfig, 104u64 => Self :: ConflictingConfig, 105u64 => Self
            :: OutOfRange, 200u64 => Self :: FileNotFound, 201u64 => Self ::
            PermissionDenied, 202u64 => Self :: ResourceAlloc, 203u64 => Self
            :: BadFd, 300u64 => Self :: BackendUnavailable, 301u64 => Self ::
            FeatureDisabled, 302u64 => Self :: DiskFormatError, 400u64 => Self
            :: AlreadyStarted, 401u64 => Self :: ValidationFailed, 402u64 =>
            Self :: HypervisorError, 403u64 => Self :: BootError, 900u64 =>
            Self :: Internal, other => panic!
            ("unknown {} error code {}", "Error", other),
        }
    }
} impl std :: fmt :: Display for Error
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result
    {
        match self
        {
            Self :: InvalidParam => write! (f, "invalid param"), Self ::
            DuplicateDevice => write! (f, "duplicate device"), Self ::
            DeviceLimitExceeded => write! (f, "device limit exceeded"), Self
            :: MissingConfig => write! (f, "missing config"), Self ::
            ConflictingConfig => write! (f, "conflicting config"), Self ::
            OutOfRange => write! (f, "out of range"), Self :: FileNotFound =>
            write! (f, "file not found"), Self :: PermissionDenied => write!
            (f, "permission denied"), Self :: ResourceAlloc => write!
            (f, "resource alloc"), Self :: BadFd => write! (f, "bad fd"), Self
            :: BackendUnavailable => write! (f, "backend unavailable"), Self
            :: FeatureDisabled => write!
            (f, "feature not enabled in this build"), Self :: DiskFormatError
            => write! (f, "disk format error"), Self :: AlreadyStarted =>
            write! (f, "already started"), Self :: ValidationFailed => write!
            (f, "validation failed"), Self :: HypervisorError => write!
            (f, "hypervisor error"), Self :: BootError => write!
            (f, "boot error"), Self :: Internal => write! (f, "internal"),
        }
    }
} impl std :: error :: Error for Error {}
unsafe extern "C"
{
    pub fn
    krun_mmio_device_manager_destroy(handle : * mut core :: ffi :: c_void);
    pub fn krun_mmio_device_manager_new() -> < MmioDeviceManager < 'static >
    as ffier :: FfiType > :: CRepr; pub fn
    krun_mmio_device_manager_add(handle : * mut core :: ffi :: c_void, device
    : * mut core :: ffi :: c_void);
} pub struct MmioDeviceManager < 'a >
(* mut core :: ffi :: c_void, std :: marker :: PhantomData < & 'a () >); impl
< 'a > MmioDeviceManager < 'a >
{
    #[doc(hidden)] pub fn __from_raw(ptr : * mut core :: ffi :: c_void) ->
    Self { Self(ptr, std :: marker :: PhantomData) } #[doc(hidden)] pub fn
    __into_raw(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
} impl < 'a > ffier :: FfiHandle for MmioDeviceManager < 'a >
{
    const C_HANDLE_NAME : & 'static str = "MmioDeviceManager"; fn
    as_handle(& self) -> * mut core :: ffi :: c_void { self.0 }
} impl < 'a > ffier :: FfiType for MmioDeviceManager < 'a >
{
    type CRepr = * mut core :: ffi :: c_void; const C_TYPE_NAME : & 'static
    str = "MmioDeviceManager"; fn into_c(self) -> * mut core :: ffi :: c_void
    { self.__into_raw() } fn from_c(repr : * mut core :: ffi :: c_void) ->
    Self { Self :: __from_raw(repr) }
} impl < 'a > std :: fmt :: Debug for MmioDeviceManager < 'a >
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result { f.debug_tuple("MmioDeviceManager").field(& self.0).finish() }
} impl < 'a > MmioDeviceManager < 'a >
{
    pub fn new() -> MmioDeviceManager < 'a >
    {
        let __raw = unsafe { krun_mmio_device_manager_new() }; <
        MmioDeviceManager < 'a > as ffier :: FfiType > :: from_c(__raw)
    } pub fn add(& mut self, device : impl AttachDevice < 'a >) -> Self
    {
        unsafe
        { krun_mmio_device_manager_add(self.0, device.__into_raw_handle()) }
    }
} impl < 'a > Drop for MmioDeviceManager < 'a >
{
    fn drop(& mut self)
    { unsafe { krun_mmio_device_manager_destroy(self.0) } }
}
unsafe extern "C"
{
    pub fn krun_fs_device_destroy(handle : * mut core :: ffi :: c_void); pub
    fn
    krun_fs_device_new(tag : < & 'static str as ffier :: FfiType > :: CRepr,
    host_path : < & 'static str as ffier :: FfiType > :: CRepr, result : * mut
    < FsDevice < 'static > as ffier :: FfiType > :: CRepr) -> ffier ::
    FfierError; pub fn
    krun_fs_device_set_dax_window_size(handle : * mut core :: ffi :: c_void,
    bytes : < u64 as ffier :: FfiType > :: CRepr);
} pub struct FsDevice < 'a >
(* mut core :: ffi :: c_void, std :: marker :: PhantomData < & 'a () >); impl
< 'a > FsDevice < 'a >
{
    #[doc(hidden)] pub fn __from_raw(ptr : * mut core :: ffi :: c_void) ->
    Self { Self(ptr, std :: marker :: PhantomData) } #[doc(hidden)] pub fn
    __into_raw(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
} impl < 'a > ffier :: FfiHandle for FsDevice < 'a >
{
    const C_HANDLE_NAME : & 'static str = "FsDevice"; fn as_handle(& self) ->
    * mut core :: ffi :: c_void { self.0 }
} impl < 'a > ffier :: FfiType for FsDevice < 'a >
{
    type CRepr = * mut core :: ffi :: c_void; const C_TYPE_NAME : & 'static
    str = "FsDevice"; fn into_c(self) -> * mut core :: ffi :: c_void
    { self.__into_raw() } fn from_c(repr : * mut core :: ffi :: c_void) ->
    Self { Self :: __from_raw(repr) }
} impl < 'a > std :: fmt :: Debug for FsDevice < 'a >
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result { f.debug_tuple("FsDevice").field(& self.0).finish() }
} impl < 'a > FsDevice < 'a >
{
    pub fn new(tag : & str, host_path : & str) -> Result < FsDevice < 'a > ,
    Error >
    {
        let mut __out = std :: mem :: MaybeUninit :: uninit(); let __err =
        unsafe
        {
            krun_fs_device_new(< & str as ffier :: FfiType > :: into_c(tag), <
            & str as ffier :: FfiType > :: into_c(host_path),
            __out.as_mut_ptr())
        }; if __err.code == 0
        {
            Ok(< FsDevice < 'a > as ffier :: FfiType > ::
            from_c(unsafe { __out.assume_init() }))
        } else { Err(Error :: from_ffi(__err)) }
    } pub fn set_dax_window_size(& mut self, bytes : u64)
    {
        unsafe
        {
            krun_fs_device_set_dax_window_size(self.0, < u64 as ffier ::
            FfiType > :: into_c(bytes))
        }
    }
} impl < 'a > Drop for FsDevice < 'a >
{ fn drop(& mut self) { unsafe { krun_fs_device_destroy(self.0) } } }
unsafe extern "C"
{
    pub fn krun_console_device_destroy(handle : * mut core :: ffi :: c_void);
    pub fn krun_console_device_builder() -> < ConsoleBuilder < 'static > as
    ffier :: FfiType > :: CRepr;
} pub struct ConsoleDevice < 'a >
(* mut core :: ffi :: c_void, std :: marker :: PhantomData < & 'a () >); impl
< 'a > ConsoleDevice < 'a >
{
    #[doc(hidden)] pub fn __from_raw(ptr : * mut core :: ffi :: c_void) ->
    Self { Self(ptr, std :: marker :: PhantomData) } #[doc(hidden)] pub fn
    __into_raw(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
} impl < 'a > ffier :: FfiHandle for ConsoleDevice < 'a >
{
    const C_HANDLE_NAME : & 'static str = "ConsoleDevice"; fn
    as_handle(& self) -> * mut core :: ffi :: c_void { self.0 }
} impl < 'a > ffier :: FfiType for ConsoleDevice < 'a >
{
    type CRepr = * mut core :: ffi :: c_void; const C_TYPE_NAME : & 'static
    str = "ConsoleDevice"; fn into_c(self) -> * mut core :: ffi :: c_void
    { self.__into_raw() } fn from_c(repr : * mut core :: ffi :: c_void) ->
    Self { Self :: __from_raw(repr) }
} impl < 'a > std :: fmt :: Debug for ConsoleDevice < 'a >
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result { f.debug_tuple("ConsoleDevice").field(& self.0).finish() }
} impl < 'a > ConsoleDevice < 'a >
{
    pub fn builder() -> ConsoleBuilder < 'a >
    {
        let __raw = unsafe { krun_console_device_builder() }; < ConsoleBuilder
        < 'a > as ffier :: FfiType > :: from_c(__raw)
    }
} impl < 'a > Drop for ConsoleDevice < 'a >
{ fn drop(& mut self) { unsafe { krun_console_device_destroy(self.0) } } }
unsafe extern "C"
{
    pub fn krun_console_builder_destroy(handle : * mut core :: ffi :: c_void);
    pub fn
    krun_console_builder_add_tty_port(handle : * mut core :: ffi :: c_void,
    name : < & 'static str as ffier :: FfiType > :: CRepr, tty_fd : <
    BorrowedFd < 'static > as ffier :: FfiType > :: CRepr, result : * mut <
    u32 as ffier :: FfiType > :: CRepr) -> ffier :: FfierError; pub fn
    krun_console_builder_set_kernel_console(handle : * mut core :: ffi ::
    c_void, port_index : < u32 as ffier :: FfiType > :: CRepr) -> ffier ::
    FfierError; pub fn
    krun_console_builder_build(handle : * mut core :: ffi :: c_void, result :
    * mut < ConsoleDevice < 'static > as ffier :: FfiType > :: CRepr) -> ffier
    :: FfierError;
} pub struct ConsoleBuilder < 'a >
(* mut core :: ffi :: c_void, std :: marker :: PhantomData < & 'a () >); impl
< 'a > ConsoleBuilder < 'a >
{
    #[doc(hidden)] pub fn __from_raw(ptr : * mut core :: ffi :: c_void) ->
    Self { Self(ptr, std :: marker :: PhantomData) } #[doc(hidden)] pub fn
    __into_raw(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
} impl < 'a > ffier :: FfiHandle for ConsoleBuilder < 'a >
{
    const C_HANDLE_NAME : & 'static str = "ConsoleBuilder"; fn
    as_handle(& self) -> * mut core :: ffi :: c_void { self.0 }
} impl < 'a > ffier :: FfiType for ConsoleBuilder < 'a >
{
    type CRepr = * mut core :: ffi :: c_void; const C_TYPE_NAME : & 'static
    str = "ConsoleBuilder"; fn into_c(self) -> * mut core :: ffi :: c_void
    { self.__into_raw() } fn from_c(repr : * mut core :: ffi :: c_void) ->
    Self { Self :: __from_raw(repr) }
} impl < 'a > std :: fmt :: Debug for ConsoleBuilder < 'a >
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result { f.debug_tuple("ConsoleBuilder").field(& self.0).finish() }
} impl < 'a > ConsoleBuilder < 'a >
{
    pub fn add_tty_port(& mut self, name : & str, tty_fd : BorrowedFd < 'a >)
    -> Result < u32, Error >
    {
        let mut __out = std :: mem :: MaybeUninit :: uninit(); let __err =
        unsafe
        {
            krun_console_builder_add_tty_port(self.0, < & str as ffier ::
            FfiType > :: into_c(name), < BorrowedFd < 'a > as ffier :: FfiType
            > :: into_c(tty_fd), __out.as_mut_ptr())
        }; if __err.code == 0
        {
            Ok(< u32 as ffier :: FfiType > ::
            from_c(unsafe { __out.assume_init() }))
        } else { Err(Error :: from_ffi(__err)) }
    } pub fn set_kernel_console(& mut self, port_index : u32) -> Result < (),
    Error >
    {
        let __err = unsafe
        {
            krun_console_builder_set_kernel_console(self.0, < u32 as ffier ::
            FfiType > :: into_c(port_index))
        }; if __err.code == 0 { Ok(()) } else
        { Err(Error :: from_ffi(__err)) }
    } pub fn build(self,) -> Result < ConsoleDevice < 'a > , Error >
    {
        let __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        mut __out = std :: mem :: MaybeUninit :: uninit(); let __err = unsafe
        { krun_console_builder_build(__handle, __out.as_mut_ptr()) }; if
        __err.code == 0
        {
            Ok(< ConsoleDevice < 'a > as ffier :: FfiType > ::
            from_c(unsafe { __out.assume_init() }))
        } else { Err(Error :: from_ffi(__err)) }
    }
} impl < 'a > Drop for ConsoleBuilder < 'a >
{ fn drop(& mut self) { unsafe { krun_console_builder_destroy(self.0) } } }
unsafe extern "C"
{
    pub fn krun_balloon_device_destroy(handle : * mut core :: ffi :: c_void);
    pub fn
    krun_balloon_device_new(result : * mut < BalloonDevice as ffier :: FfiType
    > :: CRepr) -> ffier :: FfierError;
} pub struct BalloonDevice(* mut core :: ffi :: c_void); impl BalloonDevice
{
    #[doc(hidden)] pub fn __from_raw(ptr : * mut core :: ffi :: c_void) ->
    Self { Self(ptr) } #[doc(hidden)] pub fn __into_raw(self) -> * mut core ::
    ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
} impl ffier :: FfiHandle for BalloonDevice
{
    const C_HANDLE_NAME : & 'static str = "BalloonDevice"; fn
    as_handle(& self) -> * mut core :: ffi :: c_void { self.0 }
} impl ffier :: FfiType for BalloonDevice
{
    type CRepr = * mut core :: ffi :: c_void; const C_TYPE_NAME : & 'static
    str = "BalloonDevice"; fn into_c(self) -> * mut core :: ffi :: c_void
    { self.__into_raw() } fn from_c(repr : * mut core :: ffi :: c_void) ->
    Self { Self :: __from_raw(repr) }
} impl std :: fmt :: Debug for BalloonDevice
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result { f.debug_tuple("BalloonDevice").field(& self.0).finish() }
} impl BalloonDevice
{
    pub fn new() -> Result < BalloonDevice, Error >
    {
        let mut __out = std :: mem :: MaybeUninit :: uninit(); let __err =
        unsafe { krun_balloon_device_new(__out.as_mut_ptr()) }; if __err.code
        == 0
        {
            Ok(< BalloonDevice as ffier :: FfiType > ::
            from_c(unsafe { __out.assume_init() }))
        } else { Err(Error :: from_ffi(__err)) }
    }
} impl Drop for BalloonDevice
{ fn drop(& mut self) { unsafe { krun_balloon_device_destroy(self.0) } } }
unsafe extern "C"
{
    pub fn krun_rng_device_destroy(handle : * mut core :: ffi :: c_void); pub
    fn
    krun_rng_device_new(result : * mut < RngDevice as ffier :: FfiType > ::
    CRepr) -> ffier :: FfierError;
} pub struct RngDevice(* mut core :: ffi :: c_void); impl RngDevice
{
    #[doc(hidden)] pub fn __from_raw(ptr : * mut core :: ffi :: c_void) ->
    Self { Self(ptr) } #[doc(hidden)] pub fn __into_raw(self) -> * mut core ::
    ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
} impl ffier :: FfiHandle for RngDevice
{
    const C_HANDLE_NAME : & 'static str = "RngDevice"; fn as_handle(& self) ->
    * mut core :: ffi :: c_void { self.0 }
} impl ffier :: FfiType for RngDevice
{
    type CRepr = * mut core :: ffi :: c_void; const C_TYPE_NAME : & 'static
    str = "RngDevice"; fn into_c(self) -> * mut core :: ffi :: c_void
    { self.__into_raw() } fn from_c(repr : * mut core :: ffi :: c_void) ->
    Self { Self :: __from_raw(repr) }
} impl std :: fmt :: Debug for RngDevice
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result { f.debug_tuple("RngDevice").field(& self.0).finish() }
} impl RngDevice
{
    pub fn new() -> Result < RngDevice, Error >
    {
        let mut __out = std :: mem :: MaybeUninit :: uninit(); let __err =
        unsafe { krun_rng_device_new(__out.as_mut_ptr()) }; if __err.code == 0
        {
            Ok(< RngDevice as ffier :: FfiType > ::
            from_c(unsafe { __out.assume_init() }))
        } else { Err(Error :: from_ffi(__err)) }
    }
} impl Drop for RngDevice
{ fn drop(& mut self) { unsafe { krun_rng_device_destroy(self.0) } } }
unsafe extern "C"
{
    pub fn krun_init_destroy(handle : * mut core :: ffi :: c_void); pub fn
    krun_init_builder(_rootfs : < & 'static FsDevice < 'static > as ffier ::
    FfiType > :: CRepr, console : < & 'static mut ConsoleBuilder < 'static >
    as ffier :: FfiType > :: CRepr) -> < InitBuilder < 'static, 'static > as
    ffier :: FfiType > :: CRepr;
} pub struct Init(* mut core :: ffi :: c_void); impl Init
{
    #[doc(hidden)] pub fn __from_raw(ptr : * mut core :: ffi :: c_void) ->
    Self { Self(ptr) } #[doc(hidden)] pub fn __into_raw(self) -> * mut core ::
    ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
} impl ffier :: FfiHandle for Init
{
    const C_HANDLE_NAME : & 'static str = "Init"; fn as_handle(& self) -> *
    mut core :: ffi :: c_void { self.0 }
} impl ffier :: FfiType for Init
{
    type CRepr = * mut core :: ffi :: c_void; const C_TYPE_NAME : & 'static
    str = "Init"; fn into_c(self) -> * mut core :: ffi :: c_void
    { self.__into_raw() } fn from_c(repr : * mut core :: ffi :: c_void) ->
    Self { Self :: __from_raw(repr) }
} impl std :: fmt :: Debug for Init
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result { f.debug_tuple("Init").field(& self.0).finish() }
} impl Init
{
    pub fn builder < 'a, 'b >
    (_rootfs : & FsDevice < '_ > , console : & 'b mut ConsoleBuilder < 'a >)
    -> InitBuilder < 'a, 'b >
    {
        let __raw = unsafe
        {
            krun_init_builder(< & FsDevice < '_ > as ffier :: FfiType > ::
            into_c(_rootfs), < & 'b mut ConsoleBuilder < 'a > as ffier ::
            FfiType > :: into_c(console))
        }; < InitBuilder < 'a, 'b > as ffier :: FfiType > :: from_c(__raw)
    }
} impl Drop for Init
{ fn drop(& mut self) { unsafe { krun_init_destroy(self.0) } } }
unsafe extern "C"
{
    pub fn krun_init_builder_destroy(handle : * mut core :: ffi :: c_void);
    pub fn
    krun_init_builder_console_auto(handle : * mut * mut core :: ffi :: c_void)
    -> ffier :: FfierError; pub fn
    krun_init_builder_console_tty(handle : * mut * mut core :: ffi :: c_void,
    tty_fd : < BorrowedFd < 'static > as ffier :: FfiType > :: CRepr) -> ffier
    :: FfierError; pub fn
    krun_init_builder_console_redirects(handle : * mut * mut core :: ffi ::
    c_void, stdin_fd : < i32 as ffier :: FfiType > :: CRepr, stdout_fd : < i32
    as ffier :: FfiType > :: CRepr, stderr_fd : < i32 as ffier :: FfiType > ::
    CRepr) -> ffier :: FfierError; pub fn
    krun_init_builder_exec(handle : * mut * mut core :: ffi :: c_void,
    exec_path : < & 'static str as ffier :: FfiType > :: CRepr, args : * const
    ffier :: FfierBytes, args_len : usize) -> ffier :: FfierError; pub fn
    krun_init_builder_env(handle : * mut * mut core :: ffi :: c_void, env : *
    const ffier :: FfierBytes, env_len : usize) -> ffier :: FfierError; pub fn
    krun_init_builder_workdir(handle : * mut * mut core :: ffi :: c_void, path
    : < & 'static str as ffier :: FfiType > :: CRepr) -> ffier :: FfierError;
    pub fn
    krun_init_builder_build(handle : * mut core :: ffi :: c_void, result : *
    mut < Init as ffier :: FfiType > :: CRepr) -> ffier :: FfierError;
} pub struct InitBuilder < 'a, 'b >
(* mut core :: ffi :: c_void, std :: marker :: PhantomData <
(& 'a (), & 'b ()) >); impl < 'a, 'b > InitBuilder < 'a, 'b >
{
    #[doc(hidden)] pub fn __from_raw(ptr : * mut core :: ffi :: c_void) ->
    Self { Self(ptr, std :: marker :: PhantomData) } #[doc(hidden)] pub fn
    __into_raw(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
} impl < 'a, 'b > ffier :: FfiHandle for InitBuilder < 'a, 'b >
{
    const C_HANDLE_NAME : & 'static str = "InitBuilder"; fn as_handle(& self)
    -> * mut core :: ffi :: c_void { self.0 }
} impl < 'a, 'b > ffier :: FfiType for InitBuilder < 'a, 'b >
{
    type CRepr = * mut core :: ffi :: c_void; const C_TYPE_NAME : & 'static
    str = "InitBuilder"; fn into_c(self) -> * mut core :: ffi :: c_void
    { self.__into_raw() } fn from_c(repr : * mut core :: ffi :: c_void) ->
    Self { Self :: __from_raw(repr) }
} impl < 'a, 'b > std :: fmt :: Debug for InitBuilder < 'a, 'b >
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result { f.debug_tuple("InitBuilder").field(& self.0).finish() }
} impl < 'a, 'b > InitBuilder < 'a, 'b >
{
    #[doc = " Auto-detect console setup."] #[doc = ""]
    #[doc =
    " Tries /dev/tty (the controlling terminal) first. If available, creates"]
    #[doc =
    " a single TTY port for payload I/O. Otherwise falls back to separate"]
    #[doc =
    " krun-payload-stdin/stdout/stderr redirect ports on the stdio fds."] pub
    fn console_auto(self,) -> Result < Self, Error >
    {
        let mut __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        __err = unsafe { krun_init_builder_console_auto(& mut __handle,) }; if
        __err.code == 0 { Ok(Self(__handle, std :: marker :: PhantomData)) }
        else { Err(Error :: from_ffi(__err)) }
    } pub fn console_tty(self, tty_fd : BorrowedFd < 'a >) -> Result < Self,
    Error >
    {
        let mut __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        __err = unsafe
        {
            krun_init_builder_console_tty(& mut __handle, < BorrowedFd < 'a >
            as ffier :: FfiType > :: into_c(tty_fd))
        }; if __err.code == 0
        { Ok(Self(__handle, std :: marker :: PhantomData)) } else
        { Err(Error :: from_ffi(__err)) }
    } pub fn
    console_redirects(self, stdin_fd : i32, stdout_fd : i32, stderr_fd : i32)
    -> Result < Self, Error >
    {
        let mut __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        __err = unsafe
        {
            krun_init_builder_console_redirects(& mut __handle, < i32 as ffier
            :: FfiType > :: into_c(stdin_fd), < i32 as ffier :: FfiType > ::
            into_c(stdout_fd), < i32 as ffier :: FfiType > ::
            into_c(stderr_fd))
        }; if __err.code == 0
        { Ok(Self(__handle, std :: marker :: PhantomData)) } else
        { Err(Error :: from_ffi(__err)) }
    } pub fn exec(self, exec_path : & str, args : & [& str]) -> Result < Self,
    Error >
    {
        let mut __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        __ffi_strs : Vec < ffier :: FfierBytes > =
        args.iter().map(| s | unsafe
        { ffier :: FfierBytes :: from_str(s) }).collect(); let __err = unsafe
        {
            krun_init_builder_exec(& mut __handle, < & str as ffier :: FfiType
            > :: into_c(exec_path), __ffi_strs.as_ptr(), __ffi_strs.len())
        }; if __err.code == 0
        { Ok(Self(__handle, std :: marker :: PhantomData)) } else
        { Err(Error :: from_ffi(__err)) }
    } pub fn env(self, env : & [& str]) -> Result < Self, Error >
    {
        let mut __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        __ffi_strs : Vec < ffier :: FfierBytes > =
        env.iter().map(| s | unsafe
        { ffier :: FfierBytes :: from_str(s) }).collect(); let __err = unsafe
        {
            krun_init_builder_env(& mut __handle, __ffi_strs.as_ptr(),
            __ffi_strs.len())
        }; if __err.code == 0
        { Ok(Self(__handle, std :: marker :: PhantomData)) } else
        { Err(Error :: from_ffi(__err)) }
    } pub fn workdir(self, path : & str) -> Result < Self, Error >
    {
        let mut __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        __err = unsafe
        {
            krun_init_builder_workdir(& mut __handle, < & str as ffier ::
            FfiType > :: into_c(path))
        }; if __err.code == 0
        { Ok(Self(__handle, std :: marker :: PhantomData)) } else
        { Err(Error :: from_ffi(__err)) }
    } pub fn build(self,) -> Result < Init, Error >
    {
        let __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        mut __out = std :: mem :: MaybeUninit :: uninit(); let __err = unsafe
        { krun_init_builder_build(__handle, __out.as_mut_ptr()) }; if
        __err.code == 0
        {
            Ok(< Init as ffier :: FfiType > ::
            from_c(unsafe { __out.assume_init() }))
        } else { Err(Error :: from_ffi(__err)) }
    }
} impl < 'a, 'b > Drop for InitBuilder < 'a, 'b >
{ fn drop(& mut self) { unsafe { krun_init_builder_destroy(self.0) } } }
unsafe extern "C"
{
    pub fn krun_vmm_builder_destroy(handle : * mut core :: ffi :: c_void); pub
    fn krun_vmm_builder_new() -> < VmmBuilder < 'static > as ffier :: FfiType
    > :: CRepr; pub fn
    krun_vmm_builder_vcpus(handle : * mut * mut core :: ffi :: c_void, count :
    < u8 as ffier :: FfiType > :: CRepr) -> ffier :: FfierError; pub fn
    krun_vmm_builder_ram_mib(handle : * mut * mut core :: ffi :: c_void, mib :
    < u32 as ffier :: FfiType > :: CRepr) -> ffier :: FfierError; pub fn
    krun_vmm_builder_payload(handle : * mut * mut core :: ffi :: c_void,
    payload : * mut core :: ffi :: c_void); pub fn
    krun_vmm_builder_devices(handle : * mut * mut core :: ffi :: c_void,
    devices : < MmioDeviceManager < 'static > as ffier :: FfiType > :: CRepr);
    pub fn
    krun_vmm_builder_build(handle : * mut core :: ffi :: c_void, result : *
    mut < Vmm < 'static > as ffier :: FfiType > :: CRepr) -> ffier ::
    FfierError;
} pub struct VmmBuilder < 'a >
(* mut core :: ffi :: c_void, std :: marker :: PhantomData < & 'a () >); impl
< 'a > VmmBuilder < 'a >
{
    #[doc(hidden)] pub fn __from_raw(ptr : * mut core :: ffi :: c_void) ->
    Self { Self(ptr, std :: marker :: PhantomData) } #[doc(hidden)] pub fn
    __into_raw(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
} impl < 'a > ffier :: FfiHandle for VmmBuilder < 'a >
{
    const C_HANDLE_NAME : & 'static str = "VmmBuilder"; fn as_handle(& self)
    -> * mut core :: ffi :: c_void { self.0 }
} impl < 'a > ffier :: FfiType for VmmBuilder < 'a >
{
    type CRepr = * mut core :: ffi :: c_void; const C_TYPE_NAME : & 'static
    str = "VmmBuilder"; fn into_c(self) -> * mut core :: ffi :: c_void
    { self.__into_raw() } fn from_c(repr : * mut core :: ffi :: c_void) ->
    Self { Self :: __from_raw(repr) }
} impl < 'a > std :: fmt :: Debug for VmmBuilder < 'a >
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result { f.debug_tuple("VmmBuilder").field(& self.0).finish() }
} impl < 'a > VmmBuilder < 'a >
{
    pub fn new() -> VmmBuilder < 'a >
    {
        let __raw = unsafe { krun_vmm_builder_new() }; < VmmBuilder < 'a > as
        ffier :: FfiType > :: from_c(__raw)
    } pub fn vcpus(self, count : u8) -> Result < Self, Error >
    {
        let mut __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        __err = unsafe
        {
            krun_vmm_builder_vcpus(& mut __handle, < u8 as ffier :: FfiType >
            :: into_c(count))
        }; if __err.code == 0
        { Ok(Self(__handle, std :: marker :: PhantomData)) } else
        { Err(Error :: from_ffi(__err)) }
    } pub fn ram_mib(self, mib : u32) -> Result < Self, Error >
    {
        let mut __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        __err = unsafe
        {
            krun_vmm_builder_ram_mib(& mut __handle, < u32 as ffier :: FfiType
            > :: into_c(mib))
        }; if __err.code == 0
        { Ok(Self(__handle, std :: marker :: PhantomData)) } else
        { Err(Error :: from_ffi(__err)) }
    } pub fn payload(self, payload : impl Payload) -> Self
    {
        let mut __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; unsafe
        {
            krun_vmm_builder_payload(& mut __handle,
            payload.__into_raw_handle())
        }; Self(__handle, std :: marker :: PhantomData)
    } pub fn devices(self, devices : MmioDeviceManager < 'a >) -> Self
    {
        let mut __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; unsafe
        {
            krun_vmm_builder_devices(& mut __handle, < MmioDeviceManager < 'a
            > as ffier :: FfiType > :: into_c(devices))
        }; Self(__handle, std :: marker :: PhantomData)
    } pub fn build(self,) -> Result < Vmm < 'a > , Error >
    {
        let __handle =
        { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }; let
        mut __out = std :: mem :: MaybeUninit :: uninit(); let __err = unsafe
        { krun_vmm_builder_build(__handle, __out.as_mut_ptr()) }; if
        __err.code == 0
        {
            Ok(< Vmm < 'a > as ffier :: FfiType > ::
            from_c(unsafe { __out.assume_init() }))
        } else { Err(Error :: from_ffi(__err)) }
    }
} impl < 'a > Drop for VmmBuilder < 'a >
{ fn drop(& mut self) { unsafe { krun_vmm_builder_destroy(self.0) } } }
unsafe extern "C"
{
    pub fn krun_vmm_destroy(handle : * mut core :: ffi :: c_void); pub fn
    krun_vmm_run(handle : * mut core :: ffi :: c_void);
} pub struct Vmm < 'a >
(* mut core :: ffi :: c_void, std :: marker :: PhantomData < & 'a () >); impl
< 'a > Vmm < 'a >
{
    #[doc(hidden)] pub fn __from_raw(ptr : * mut core :: ffi :: c_void) ->
    Self { Self(ptr, std :: marker :: PhantomData) } #[doc(hidden)] pub fn
    __into_raw(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
} impl < 'a > ffier :: FfiHandle for Vmm < 'a >
{
    const C_HANDLE_NAME : & 'static str = "Vmm"; fn as_handle(& self) -> * mut
    core :: ffi :: c_void { self.0 }
} impl < 'a > ffier :: FfiType for Vmm < 'a >
{
    type CRepr = * mut core :: ffi :: c_void; const C_TYPE_NAME : & 'static
    str = "Vmm"; fn into_c(self) -> * mut core :: ffi :: c_void
    { self.__into_raw() } fn from_c(repr : * mut core :: ffi :: c_void) ->
    Self { Self :: __from_raw(repr) }
} impl < 'a > std :: fmt :: Debug for Vmm < 'a >
{
    fn fmt(& self, f : & mut std :: fmt :: Formatter < '_ >) -> std :: fmt ::
    Result { f.debug_tuple("Vmm").field(& self.0).finish() }
} impl < 'a > Vmm < 'a >
{ pub fn run(& mut self,) { unsafe { krun_vmm_run(self.0,) } } } impl < 'a >
Drop for Vmm < 'a >
{ fn drop(& mut self) { unsafe { krun_vmm_destroy(self.0) } } }
pub trait Payload
{
    #[doc(hidden)] fn __into_raw_handle(self) -> * mut core :: ffi :: c_void
    where Self : Sized;
} unsafe extern "C" {} impl Payload for Init
{
    fn __into_raw_handle(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
}
pub trait AttachDevice < 'a >
{
    #[doc(hidden)] fn __into_raw_handle(self) -> * mut core :: ffi :: c_void
    where Self : Sized;
} unsafe extern "C" {} impl < 'a > AttachDevice < 'a > for FsDevice < 'a >
{
    fn __into_raw_handle(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
}
unsafe extern "C" {} impl < 'a > AttachDevice < 'a > for ConsoleDevice < 'a >
{
    fn __into_raw_handle(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
}
unsafe extern "C" {} impl < 'a > AttachDevice < 'a > for BalloonDevice < 'a >
{
    fn __into_raw_handle(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
}
unsafe extern "C" {} impl < 'a > AttachDevice < 'a > for RngDevice < 'a >
{
    fn __into_raw_handle(self) -> * mut core :: ffi :: c_void
    { let this = std :: mem :: ManuallyDrop :: new(self); this.0 }
}

use std::path::PathBuf;

use init_blob::INIT_PATH;

use super::error::{DetailedError, Error};

// ---------------------------------------------------------------------------
// KrunPayload trait — payloads know how to configure the VM for boot
// ---------------------------------------------------------------------------

/// Internal trait for payload types that know how to configure the VM for boot.
///
/// This trait is not part of the public API. Use [`Payload`] instead.
pub trait KrunPayload: Send {
    /// Configure the kernel cmdline with payload-specific parameters.
    /// Called before devices are attached. Only used when the payload provides
    /// a krunfw-style kernel bundle (not an external kernel).
    fn configure_cmdline(
        &self,
        cmdline: &mut kernel::cmdline::Cmdline,
    ) -> Result<(), DetailedError>;

    /// Return the args epilog to append after device params (e.g. "-- arg1 arg2").
    /// Returns empty string if none.
    fn cmdline_epilog(&self) -> &str;

    /// Load the kernel and choose the payload type for boot.
    ///
    /// Returns `(Option<KernelBundle>, Payload)`:
    /// - `None` kernel bundle + `Payload::ExternalKernel` for external kernels (e.g. FreeBSD)
    /// - `Some(bundle)` + `Payload::KernelMmap/KernelCopy` for krunfw payloads
    fn load_kernel_and_choose_payload(
        &self,
    ) -> Result<
        (
            Option<vmm::vmm_config::kernel_bundle::KernelBundle>,
            vmm::builder::Payload,
        ),
        DetailedError,
    >;
}

// ---------------------------------------------------------------------------
// Krunfw — kernel payload loaded from libkrunfw
// ---------------------------------------------------------------------------

/// A kernel payload loaded from libkrunfw.
///
/// Loads the kernel from the libkrunfw shared library and sets
/// `init=/init.krun` on the kernel cmdline. The init binary and
/// its config JSON must be injected into the rootfs separately
/// via [`FsDevice::inject`].
///
/// # Example
///
/// ```no_run
/// let config = InitConfig::builder()
///     .entrypoint(&["/bin/sh"])
///     .build();
///
/// let mut rootfs = FsDevice::new("/dev/root", "/path/to/rootfs")?;
/// rootfs.inject(&config.guest_files());
///
/// let payload = Krunfw::load();
/// ```
pub struct Krunfw {
    block_root: Option<BlockRootConfig>,
    dhcp_client: bool,
}

struct BlockRootConfig {
    device: String,
    fstype: Option<String>,
    options: Option<String>,
}

// TODO: Krunfw::load() should eagerly load libkrunfw and return Result<Self, Error>.
// Currently the library is loaded lazily in load_kernel(). Fix in the
// remove-implicit-stuff PR.
#[ffier::exportable]
impl Krunfw {
    /// Load the krunfw kernel payload.
    pub fn load() -> Self {
        Krunfw {
            block_root: None,
            dhcp_client: false,
        }
    }
}

impl Krunfw {
    /// Configure the init to pivot from the initial (NullFs) root to a
    /// block device after boot.
    ///
    /// The init process will mount `device` as `fstype` and pivot_root to it.
    // TODO: expose via ffier once it supports Option<&str> params
    pub fn set_block_root(&mut self, device: &str, fstype: Option<&str>, options: Option<&str>) {
        self.block_root = Some(BlockRootConfig {
            device: device.to_string(),
            fstype: fstype.map(|s| s.to_string()),
            options: options.map(|s| s.to_string()),
        });
    }

    /// Enable the in-guest DHCP client for network autoconfiguration.
    pub fn enable_dhcp_client(&mut self) {
        self.dhcp_client = true;
    }
}

// ---------------------------------------------------------------------------
// FreeBsdPayload — external kernel payload for FreeBSD guests
// ---------------------------------------------------------------------------

/// The format of the FreeBSD kernel image.
#[derive(Clone, Debug)]
pub enum FreeBsdKernelFormat {
    /// ELF image (x86_64).
    Elf,
    /// Raw binary image (aarch64).
    Raw,
}

/// A payload that boots a FreeBSD guest from an external kernel image.
///
/// FreeBSD requires:
/// - An external kernel (ELF on x86_64, raw binary on aarch64)
/// - A serial console for I/O (virtio console is not supported by FreeBSD)
/// - Block devices for the rootfs ISO and config ISO
///
/// Use [`VmmBuilder::serial_input_fd`] to provide a pipe fd for serial input.
/// Add [`BlockDevice`]s for `"vtbd0"` (rootfs) and `"vtbd1"` (config) to the
/// device manager.
///
/// # Example (x86_64)
///
/// ```no_run
/// let payload = FreeBsdPayload::new(
///     kernel_path,
///     FreeBsdKernelFormat::Elf,
///     "vfs.root.mountfrom=cd9660:/dev/vtbd0 boot_mute=YES init_path=/init-freebsd",
/// );
/// ```
pub struct FreeBsdPayload {
    kernel_path: PathBuf,
    format: FreeBsdKernelFormat,
    cmdline: String,
}

impl FreeBsdPayload {
    /// Create a new FreeBSD payload.
    ///
    /// # Arguments
    ///
    /// - `kernel_path`: path to the FreeBSD kernel image on the host.
    /// - `format`: the kernel image format (ELF for x86_64, Raw for aarch64).
    /// - `cmdline`: the kernel command line (e.g. `"vfs.root.mountfrom=cd9660:/dev/vtbd0 boot_mute=YES init_path=/init-freebsd"`).
    pub fn new(
        kernel_path: PathBuf,
        format: FreeBsdKernelFormat,
        cmdline: impl Into<String>,
    ) -> Self {
        Self {
            kernel_path,
            format,
            cmdline: cmdline.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Payload — FFI boundary trait for dyn_param dispatch
// ---------------------------------------------------------------------------

/// Trait for types that can be used as a VM payload.
///
/// Currently [`Krunfw`] and [`FreeBsdPayload`] implement this trait.
pub trait Payload {
    /// Convert this payload into a boxed trait object for storage in
    /// [`VmmBuilder`](super::vmm_builder::VmmBuilder).
    fn into_payload(self) -> Box<dyn KrunPayload>;
}

#[ffier::trait_impl]
impl Payload for Krunfw {
    #[ffier(skip)]
    fn into_payload(self) -> Box<dyn KrunPayload> {
        Box::new(self)
    }
}

impl Payload for FreeBsdPayload {
    fn into_payload(self) -> Box<dyn KrunPayload> {
        Box::new(self)
    }
}

// ---------------------------------------------------------------------------
// KrunPayload impl for Krunfw
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", not(feature = "tee")))]
const KRUNFW_NAME: &str = "libkrunfw.so.5";
#[cfg(all(target_os = "linux", feature = "amd-sev"))]
const KRUNFW_NAME: &str = "libkrunfw-sev.so.5";
#[cfg(all(target_os = "linux", feature = "tdx"))]
const KRUNFW_NAME: &str = "libkrunfw-tdx.so.5";
#[cfg(target_os = "macos")]
const KRUNFW_NAME: &str = "libkrunfw.5.dylib";

static KRUNFW: std::sync::LazyLock<Option<libloading::Library>> =
    std::sync::LazyLock::new(|| unsafe { libloading::Library::new(KRUNFW_NAME).ok() });

impl KrunPayload for Krunfw {
    fn configure_cmdline(
        &self,
        cmdline: &mut kernel::cmdline::Cmdline,
    ) -> Result<(), DetailedError> {
        let cmdline_base =
            vmm::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE.replace(" quiet", "");
        cmdline
            .insert_str(&format!("{cmdline_base} init={INIT_PATH}"))
            .map_err(|e| DetailedError::new(Error::Internal(), format!("{e:?}")))?;

        if self.dhcp_client {
            cmdline
                .insert_str(" KRUN_DHCP=1")
                .map_err(|e| DetailedError::new(Error::Internal(), format!("{e:?}")))?;
        }

        if let Some(br) = &self.block_root {
            cmdline
                .insert_str(&format!(" KRUN_BLOCK_ROOT_DEVICE={}", br.device))
                .map_err(|e| DetailedError::new(Error::Internal(), format!("{e:?}")))?;
            if let Some(fstype) = &br.fstype {
                cmdline
                    .insert_str(&format!(" KRUN_BLOCK_ROOT_FSTYPE={fstype}"))
                    .map_err(|e| DetailedError::new(Error::Internal(), format!("{e:?}")))?;
            }
            if let Some(options) = &br.options {
                cmdline
                    .insert_str(&format!(" KRUN_BLOCK_ROOT_OPTIONS={options}"))
                    .map_err(|e| DetailedError::new(Error::Internal(), format!("{e:?}")))?;
            }
        }

        Ok(())
    }

    fn cmdline_epilog(&self) -> &str {
        ""
    }

    fn load_kernel_and_choose_payload(
        &self,
    ) -> Result<
        (
            Option<vmm::vmm_config::kernel_bundle::KernelBundle>,
            vmm::builder::Payload,
        ),
        DetailedError,
    > {
        let lib = KRUNFW.as_ref().ok_or_else(|| {
            DetailedError::new(
                Error::FileNotFound(),
                format!("could not load {KRUNFW_NAME}"),
            )
        })?;
        let get_kernel: libloading::Symbol<
            unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut libc::c_char,
        > = unsafe {
            lib.get(b"krunfw_get_kernel")
                .map_err(|e| DetailedError::new(Error::Internal(), format!("krunfw symbol: {e}")))?
        };

        let mut guest_addr: u64 = 0;
        let mut entry_addr: u64 = 0;
        let mut size: usize = 0;
        let host_addr = unsafe { get_kernel(&mut guest_addr, &mut entry_addr, &mut size) };
        if host_addr.is_null() {
            return Err(DetailedError::new(
                Error::BootError(),
                "krunfw_get_kernel returned null",
            ));
        }
        let bundle = vmm::vmm_config::kernel_bundle::KernelBundle {
            host_addr: host_addr as u64,
            guest_addr,
            entry_addr,
            size,
        };

        let payload_type = vmm::builder::choose_payload(
            Some(&bundle),
            #[cfg(feature = "tee")]
            None,
            #[cfg(feature = "tee")]
            None,
            None, // external_kernel
            None, // firmware_config
        )
        .map_err(|e| DetailedError::new(Error::BootError(), format!("{e:?}")))?;

        Ok((Some(bundle), payload_type))
    }
}

// ---------------------------------------------------------------------------
// KrunPayload impl for FreeBsdPayload
// ---------------------------------------------------------------------------

impl KrunPayload for FreeBsdPayload {
    fn configure_cmdline(
        &self,
        _cmdline: &mut kernel::cmdline::Cmdline,
    ) -> Result<(), DetailedError> {
        // FreeBSD uses ExternalKernel which carries its own cmdline.
        // This method is only called for krunfw payloads.
        Ok(())
    }

    fn cmdline_epilog(&self) -> &str {
        ""
    }

    fn load_kernel_and_choose_payload(
        &self,
    ) -> Result<
        (
            Option<vmm::vmm_config::kernel_bundle::KernelBundle>,
            vmm::builder::Payload,
        ),
        DetailedError,
    > {
        use vmm::vmm_config::external_kernel::{ExternalKernel, KernelFormat};

        let format = match self.format {
            FreeBsdKernelFormat::Elf => KernelFormat::Elf,
            FreeBsdKernelFormat::Raw => KernelFormat::Raw,
        };

        let external_kernel = ExternalKernel {
            path: self.kernel_path.clone(),
            format,
            initramfs_path: None,
            initramfs_size: 0,
            cmdline: Some(self.cmdline.clone()),
        };

        let payload_type = vmm::builder::choose_payload(
            None,
            #[cfg(feature = "tee")]
            None,
            #[cfg(feature = "tee")]
            None,
            Some(&external_kernel),
            None,
        )
        .map_err(|e| DetailedError::new(Error::BootError(), format!("{e:?}")))?;

        Ok((None, payload_type))
    }
}

use std::path::PathBuf;

use init_blob::INIT_PATH;

use super::error::{DetailedError, Error};

// ---------------------------------------------------------------------------
// KrunPayload trait — payloads know how to configure the VM for boot
// ---------------------------------------------------------------------------

/// Loaded kernel ready for boot.
///
/// Returned by [`Krunfw::load`] or [`ExternalKernel::load`]. Pass to
/// [`VmmBuilder::kernel`].
pub struct Payload {
    pub(crate) bundle: Option<vmm::vmm_config::kernel_bundle::KernelBundle>,
    pub(crate) payload: vmm::builder::Payload,
    pub(crate) cmdline: String,
}

#[ffier::exportable]
impl Payload {
    /// Load the built-in krunfw kernel.
    pub fn load_krunfw() -> Result<Self, Error> {
        let lib = KRUNFW.as_ref().ok_or_else(|| {
            log::error!("could not load {KRUNFW_NAME}");
            Error::FileNotFound()
        })?;
        let get_kernel: libloading::Symbol<
            unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut libc::c_char,
        > = unsafe {
            lib.get(b"krunfw_get_kernel").map_err(|e| {
                log::error!("krunfw symbol: {e}");
                Error::Internal()
            })?
        };

        let mut guest_addr: u64 = 0;
        let mut entry_addr: u64 = 0;
        let mut size: usize = 0;
        let host_addr = unsafe { get_kernel(&mut guest_addr, &mut entry_addr, &mut size) };
        if host_addr.is_null() {
            log::error!("krunfw_get_kernel returned null");
            return Err(Error::BootError());
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
            None,
            None,
        )
        .map_err(|e| {
            log::error!("choose_payload: {e:?}");
            Error::BootError()
        })?;

        let cmdline = vmm::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE.replace(" quiet", "");

        Ok(Payload {
            bundle: Some(bundle),
            payload: payload_type,
            cmdline,
        })
    }

    /// Load an external kernel (Linux, FreeBSD, etc.).
    pub fn load_external(path: &str, format: KernelFormat, cmdline: &str) -> Result<Self, Error> {
        use vmm::vmm_config::external_kernel::ExternalKernel;
        use vmm::vmm_config::external_kernel::KernelFormat as VmmKernelFormat;

        let vmm_format = match format {
            KernelFormat::Elf => VmmKernelFormat::Elf,
            KernelFormat::Raw => VmmKernelFormat::Raw,
        };

        let external_kernel = ExternalKernel {
            path: PathBuf::from(path),
            format: vmm_format,
            initramfs_path: None,
            initramfs_size: 0,
            cmdline: Some(cmdline.to_string()),
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
        .map_err(|e| {
            log::error!("choose_payload: {e:?}");
            Error::BootError()
        })?;

        Ok(Payload {
            bundle: None,
            payload: payload_type,
            cmdline: cmdline.to_string(),
        })
    }

    /// The kernel cmdline (base + any appended fragments).
    pub fn cmdline(&self) -> &str {
        &self.cmdline
    }

    /// Append a fragment to the kernel cmdline.
    pub fn append_cmdline(&mut self, extra: &str) {
        if !extra.is_empty() {
            self.cmdline.push(' ');
            self.cmdline.push_str(extra);
        }
    }
}

// TODO: export apply_init_config via ffier once Bytes builtin is available
// (init_blob::Config contains guest files with &[u8] data).

impl Payload {
    /// Apply an [`InitConfig`]'s kernel cmdline requirements.
    ///
    /// Appends init-specific parameters (`init=/init.krun`, DHCP,
    /// block root, etc.) to the kernel cmdline.
    pub fn apply_init_config(&mut self, config: &init_blob::Config) {
        self.append_cmdline(config.kernel_cmdline());
    }
}

// ---------------------------------------------------------------------------
// Krunfw — kernel payload loaded from libkrunfw
// ---------------------------------------------------------------------------

/// A kernel payload loaded from libkrunfw.
///
/// Loads the kernel from the libkrunfw shared library. The kernel
/// cmdline is assembled from `init=/init.krun` plus any extras
/// from [`InitConfig::kernel_cmdline_extras()`].
///
/// # Example
///
/// ```no_run
/// let config = InitConfig::builder()
///     .args(&["/bin/sh"])
///     .dhcp(true)
///     .build();
///
/// let mut rootfs = FsDevice::new("/dev/root", "/path/to/rootfs")?;
/// rootfs.inject(&config.guest_files());
///
/// let payload = Krunfw::load();
/// ```
/// The format of the kernel image (for external kernels).
#[ffier::exportable]
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum KernelFormat {
    /// ELF image (x86_64).
    Elf,
    /// Raw binary image (aarch64).
    Raw,
}

// ---------------------------------------------------------------------------
// Payload — FFI boundary trait for dyn_param dispatch
// ---------------------------------------------------------------------------

/// Trait for types that can be used as a VM payload.
///

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

// ---------------------------------------------------------------------------

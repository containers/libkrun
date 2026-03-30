use std::os::fd::{BorrowedFd, FromRawFd};

use devices::virtio::port_io;
use libc::{STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};

use super::devices::{ConsoleBuilder, FsDevice};
use super::error::{DetailedError, Error};

// ---------------------------------------------------------------------------
// KrunPayload trait — payloads know how to configure the VM for boot
// ---------------------------------------------------------------------------

/// Internal trait for payload types that know how to configure the VM for boot.
///
/// This trait is not part of the public API. Use [`Payload`] instead.
pub trait KrunPayload: Send {
    /// Configure the kernel cmdline with payload-specific parameters.
    /// Called before devices are attached.
    fn configure_cmdline(
        &self,
        cmdline: &mut kernel::cmdline::Cmdline,
    ) -> Result<(), DetailedError>;

    /// Return the args epilog to append after device params (e.g. "-- arg1 arg2").
    /// Returns empty string if none.
    fn cmdline_epilog(&self) -> &str;

    /// Load the kernel and return the bundle. Called during VM construction.
    fn load_kernel(&self) -> Result<vmm::vmm_config::kernel_bundle::KernelBundle, DetailedError>;
}


// ---------------------------------------------------------------------------
// Init — krunfw-based payload (runs a command inside the VM)
// ---------------------------------------------------------------------------

/// A payload that runs a command inside the VM using the built-in krun init.
///
/// The init process sets up the rootfs, redirects stdio, and execs the
/// specified command. Use [`Init::builder`] to configure what to run.
pub struct Init {
    args: String,
    env: String,
}

/// Builder for configuring an `Init` payload.
///
/// Created via [`Init::builder`]. Configure the command to run with
/// [`exec`](InitBuilder::exec), optionally set environment variables
/// with [`env`](InitBuilder::env) and working directory with
/// [`workdir`](InitBuilder::workdir), then call
/// [`build`](InitBuilder::build).
pub struct InitBuilder<'a, 'b> {
    console: &'b mut ConsoleBuilder<'a>,
    exec_path: Option<String>,
    args: Option<String>,
    env: Option<String>,
    workdir: Option<String>,
    payload_console_configured: bool,
}

#[ffier::exportable]
impl Init {
    /// Create a new init payload builder.
    ///
    /// # Arguments
    ///
    /// - `_rootfs`: the root filesystem device (reserved for future validation).
    /// - `console`: console builder; an output-only port for boot messages is added automatically.
    pub fn builder<'a, 'b>(
        _rootfs: &FsDevice<'_>,
        console: &'b mut ConsoleBuilder<'a>,
    ) -> InitBuilder<'a, 'b> {
        // Port 0 is always the kernel/init console (output-only).
        // Kernel cmdline has console=hvc0, so boot messages go here.
        // init.krun's stdio starts on hvc0 too; setup_redirects() in init.krun
        // moves payload stdio to a named port (krun-tty or krun-stdin/stdout/stderr).
        console.add_console_port("krun-init-console", port_io::output_to_log(log::Level::Info));

        InitBuilder {
            console,
            exec_path: None,
            args: None,
            env: None,
            workdir: None,
            payload_console_configured: false,
        }
    }
}

#[ffier::exportable]
impl<'a, 'b> InitBuilder<'a, 'b> {
    /// Auto-detect console setup.
    ///
    /// Tries /dev/tty (the controlling terminal) first. If available, creates
    /// a single TTY port for payload I/O. Otherwise falls back to separate
    /// krun-payload-stdin/stdout/stderr redirect ports on the stdio fds.
    pub fn console_auto(mut self) -> Result<Self, Error> {
        // /dev/tty always refers to the controlling terminal, even if
        // stdin/stdout are redirected.
        if let Ok(tty) = std::fs::File::options().read(true).write(true).open("/dev/tty") {
            use std::os::fd::AsRawFd;
            let raw_fd = tty.as_raw_fd();
            std::mem::forget(tty); // leak the fd — add_tty_port dups it
            self.console_tty(unsafe { BorrowedFd::borrow_raw(raw_fd) })
        } else {
            self.console_redirects(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO)
        }
    }

    /// Set up a single TTY port for payload I/O.
    ///
    /// The payload's stdin/stdout/stderr will all be connected to this
    /// terminal. Raw mode is enabled automatically if `tty_fd` is a
    /// real terminal.
    pub fn console_tty(mut self, tty_fd: BorrowedFd<'a>) -> Result<Self, Error> {
        self.console
            .add_tty_port("krun-payload-tty", tty_fd)?;
        self.payload_console_configured = true;
        Ok(self)
    }

    /// Set up separate redirect ports for payload stdin, stdout, and stderr.
    ///
    /// Each fd is duplicated internally. Pass `-1` (or any negative value)
    /// to skip a particular stream.
    pub fn console_redirects(
        mut self,
        stdin_fd: i32,
        stdout_fd: i32,
        stderr_fd: i32,
    ) -> Result<Self, Error> {
        if stdin_fd >= 0 {
            self.console
                .add_io_port("krun-payload-stdin", Some(stdin_fd), None)?;
        }
        if stdout_fd >= 0 {
            self.console
                .add_io_port("krun-payload-stdout", None, Some(stdout_fd))?;
        }
        if stderr_fd >= 0 {
            self.console
                .add_io_port("krun-payload-stderr", None, Some(stderr_fd))?;
        }
        self.payload_console_configured = true;
        Ok(self)
    }

    /// Set the command to execute inside the guest.
    ///
    /// # Arguments
    ///
    /// - `exec_path`: absolute path to the executable within the guest rootfs.
    /// - `args`: command-line arguments (not including argv\[0\]).
    pub fn exec(mut self, exec_path: &str, args: &[&str]) -> Result<Self, Error> {
        if exec_path.is_empty() {
            return Err(Error::InvalidParam);
        }
        self.exec_path = Some(exec_path.to_string());
        let encoded: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
        self.args = Some(encoded.join(" "));
        Ok(self)
    }

    /// Set environment variables for the guest process.
    ///
    /// # Arguments
    ///
    /// - `env`: each string should be in `KEY=VALUE` format.
    pub fn env(mut self, env: &[&str]) -> Result<Self, Error> {
        let encoded: Vec<String> = env.iter().map(|e| format!("\"{e}\"")).collect();
        self.env = Some(encoded.join(" "));
        Ok(self)
    }

    /// Set the working directory for the guest process.
    ///
    /// # Arguments
    ///
    /// - `path`: absolute path within the guest rootfs.
    pub fn workdir(mut self, path: &str) -> Result<Self, Error> {
        if path.is_empty() {
            return Err(Error::InvalidParam);
        }
        self.workdir = Some(path.to_string());
        Ok(self)
    }

    /// Build the init payload.
    ///
    /// Requires [`exec`](InitBuilder::exec) to have been called. If no
    /// console was explicitly configured (via [`console_tty`](InitBuilder::console_tty)
    /// or [`console_redirects`](InitBuilder::console_redirects)), auto-detection
    /// is used: `/dev/tty` if available, otherwise stdin/stdout/stderr.
    pub fn build(mut self) -> Result<Init, Error> {
        // If the caller didn't explicitly set up console ports, auto-detect.
        if !self.payload_console_configured {
            self = self.console_auto()?;
        }

        let exec_path = self.exec_path.ok_or(Error::MissingConfig)?;
        let krun_init = format!("KRUN_INIT={exec_path}");
        let krun_workdir = self
            .workdir
            .as_ref()
            .map(|w| format!("KRUN_WORKDIR={w}"))
            .unwrap_or_default();
        let krun_env = self.env.unwrap_or_default();
        let args = self.args.unwrap_or_default();

        let env_str = format!(" {krun_init} {krun_workdir} {krun_env}");

        Ok(Init { args, env: env_str })
    }
}

// ---------------------------------------------------------------------------
// KrunPayload impl for Init
// ---------------------------------------------------------------------------

const INIT_PATH: &str = "/init.krun";

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
// Payload — FFI boundary trait for dyn_param dispatch
// ---------------------------------------------------------------------------

/// Trait for types that can be used as a VM payload.
///
/// Currently only `Init` implements this trait.
pub trait Payload {
    /// Convert this payload into a boxed trait object for storage in
    /// [`VmmBuilder`](super::vmm_builder::VmmBuilder).
    fn into_payload(self) -> Box<dyn KrunPayload>;
}

#[ffier::trait_impl]
impl Payload for Init {
    #[ffier(skip)]
    fn into_payload(self) -> Box<dyn KrunPayload> { Box::new(self) }
}

// ---------------------------------------------------------------------------
// KrunPayload impl for Init
// ---------------------------------------------------------------------------

impl KrunPayload for Init {
    fn configure_cmdline(
        &self,
        cmdline: &mut kernel::cmdline::Cmdline,
    ) -> Result<(), DetailedError> {
        let cmdline_base = vmm::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE
            .replace(" quiet", "");
        cmdline
            .insert_str(&format!("{cmdline_base} init={INIT_PATH}"))
            .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))?;
        cmdline
            .insert_str(&self.env)
            .map_err(|e| DetailedError::new(Error::Internal, format!("{e:?}")))?;
        Ok(())
    }

    fn cmdline_epilog(&self) -> &str {
        &self.args
    }

    fn load_kernel(&self) -> Result<vmm::vmm_config::kernel_bundle::KernelBundle, DetailedError> {
        let lib = KRUNFW.as_ref().ok_or_else(|| {
            DetailedError::new(
                Error::FileNotFound,
                format!("could not load {KRUNFW_NAME}"),
            )
        })?;
        let get_kernel: libloading::Symbol<
            unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut libc::c_char,
        > = unsafe {
            lib.get(b"krunfw_get_kernel")
                .map_err(|e| DetailedError::new(Error::Internal, format!("krunfw symbol: {e}")))?
        };

        let mut guest_addr: u64 = 0;
        let mut entry_addr: u64 = 0;
        let mut size: usize = 0;
        let host_addr = unsafe {
            get_kernel(&mut guest_addr, &mut entry_addr, &mut size)
        };
        if host_addr.is_null() {
            return Err(DetailedError::new(Error::BootError, "krunfw_get_kernel returned null"));
        }
        Ok(vmm::vmm_config::kernel_bundle::KernelBundle {
            host_addr: host_addr as u64,
            guest_addr,
            entry_addr,
            size,
        })
    }
}

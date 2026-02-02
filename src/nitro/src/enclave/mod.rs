// SPDX-License-Identifier: Apache-2.0

pub(crate) mod args_writer;
pub(crate) mod proxy;

use super::error::{return_code, start, Error};
use args_writer::EnclaveArgsWriter;
use nitro_enclaves::{
    launch::{ImageType, Launcher, MemoryInfo, PollTimeout, StartFlags},
    Device,
};
use proxy::{
    net::NetProxy, output::OutputProxy, signal_handler::SignalHandler, DeviceProxy, DeviceProxyList,
};
use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    os::fd::RawFd,
    path::PathBuf,
};
use tar::HeaderMode;
use vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

const KRUN_NITRO_EIF_PATH_ENV_VAR: &str = "KRUN_NITRO_EIF_PATH";
const KRUN_NITRO_EIF_PATH_DEFAULT: &str = "/usr/share/krun-nitro/krun-nitro.eif";

/// Directories within the configured rootfs that will be ignored when writing to the enclave. The
/// enclave is responsible for initializing these directories within the guest operating system.
const ROOTFS_DIR_DENYLIST: [&str; 6] = [
    "proc",                 // /proc.
    "run",                  // /run.
    "tmp",                  // /tmp.
    "dev",                  // /dev.
    "sys",                  // /sys.
    "usr/share/krun-nitro", // Cached EIF file (and possibly other metadata).
];

/// Nitro Enclave data.
pub struct NitroEnclave {
    /// Amount of RAM (in MiB).
    pub mem_size_mib: usize,
    /// Number of vCPUs.
    pub vcpus: u8,
    /// Enclave rootfs.
    pub rootfs: String,
    /// Execution path.
    pub exec_path: String,
    /// Execution args.
    pub exec_args: String,
    /// Execution environment.
    pub exec_env: String,
    /// Network proxy.
    pub net_unixfd: Option<RawFd>,
    /// Path to redirect enclave output to.
    pub output_path: PathBuf,
    /// Output kernel and initramfs debug logs from enclave.
    pub debug: bool,
}

impl NitroEnclave {
    /// Run an application within a nitro enclave.
    pub fn run(mut self) -> Result<(), Error> {
        // Collect all launch parameters (rootfs, execution arguments, device proxies) and establish
        // an enclave argument writer to write this data to the nitro enclave when started.
        let rootfs_archive = self.rootfs_archive().map_err(Error::RootFsArchive)?;
        let proxies = self.proxies().map_err(Error::DeviceProxy)?;

        let writer = EnclaveArgsWriter::new(
            &rootfs_archive,
            &self.exec_path,
            &self.exec_args,
            &self.exec_env,
            &proxies,
        );

        // Disable signals to launch enclave VM.
        self.signals(false);

        // Launch the enclave and write the configured launch parameters to the initramfs.
        let (cid, timeout) = self.start().map_err(Error::Start)?;

        writer.write_args(cid, timeout).map_err(Error::ArgsWrite)?;

        // Establish the vsock listener for the application's return code upon termination.
        let retcode_listener = VsockListener::bind(&VsockAddr::new(
            VMADDR_CID_ANY,
            cid + (VsockPortOffset::ReturnCode as u32),
        ))
        .map_err(return_code::Error::VsockBind)
        .map_err(Error::ReturnCodeListener)?;

        // Enable signals now that enclave VM is started.
        self.signals(true);

        // Run the device proxies. Each proxy is run within its own thread that can only be
        // terminated by the enclave (by closing the vsock connection).
        proxies.run(cid).map_err(Error::DeviceProxy)?;

        // In debug mode, the console device doesn't shut down until the enclave itself exits. Thus,
        // libkrun will be unable to retrieve the shutdown code from the enclave.
        if !self.debug {
            // Retrieve the application return code from the enclave.
            let ret = self
                .shutdown_ret(retcode_listener)
                .map_err(Error::ReturnCodeListener)?;

            // A non-zero return code indicates an error. Wrap this code within an Error object.
            if ret != 0 {
                return Err(Error::AppReturn(ret));
            }
        }

        Ok(())
    }

    /// Start a nitro enclave.
    fn start(&mut self) -> Result<(u32, PollTimeout), start::Error> {
        // Read the cached EIF file required to run the enclave.
        let eif = {
            let path = env::var(KRUN_NITRO_EIF_PATH_ENV_VAR)
                .unwrap_or(KRUN_NITRO_EIF_PATH_DEFAULT.to_string());

            fs::read(path).map_err(start::Error::EifRead)
        }?;

        // Calculate the poll timeout (based on the size of the EIF file and amount of RAM allocated
        // to the enclave) for the enclave to indicate that has successfully started.
        let timeout = PollTimeout::try_from((eif.as_slice(), self.mem_size_mib << 20))
            .map_err(start::Error::PollTimeoutCalculate)?;

        // Launch an enclave VM with the configured number of vCPUs and amount of RAM.
        let device = Device::open().map_err(start::Error::DeviceOpen)?;

        let mut launcher = Launcher::new(&device).map_err(start::Error::VmCreate)?;

        let mem = MemoryInfo::new(ImageType::Eif(&eif), self.mem_size_mib);
        launcher
            .set_memory(mem)
            .map_err(start::Error::VmMemorySet)?;

        for _ in 0..self.vcpus {
            launcher.add_vcpu(None).map_err(start::Error::VcpuAdd)?;
        }

        // Indicate to the enclave to start in debug mode if configured.
        let mut start_flags = StartFlags::empty();

        if self.debug {
            start_flags |= StartFlags::DEBUG;
        }

        // Start the enclave.
        let cid = launcher
            .start(start_flags, None)
            .map_err(start::Error::VmStart)?;

        // Safe to unwrap.
        Ok((cid.try_into().unwrap(), timeout))
    }

    /// Initialize and collect all device proxies used for the enclave.
    fn proxies(&self) -> Result<DeviceProxyList, proxy::Error> {
        let mut proxies: Vec<Box<dyn Send + DeviceProxy>> = vec![];

        // All enclaves will include a proxy for debug/application output.
        let output = OutputProxy::new(&self.output_path, self.debug)?;
        proxies.push(Box::new(output));

        if let Some(fd) = self.net_unixfd {
            let net = NetProxy::try_from(fd)?;
            proxies.push(Box::new(net));
        }

        // All enclaves will include a proxy for signal handling (e.g. forwarding SIGTERM signals to
        // application running within the enclave).
        proxies.push(Box::new(SignalHandler::new()?));

        Ok(DeviceProxyList(proxies))
    }

    /// Produce a tarball of the enclave's rootfs (to be written to and extracted by the enclave
    /// initramfs).
    fn rootfs_archive(&self) -> Result<Vec<u8>, io::Error> {
        let mut builder = tar::Builder::new(Vec::new());

        builder.mode(HeaderMode::Deterministic);
        builder.follow_symlinks(false);

        let pathbuf = PathBuf::from(self.rootfs.clone());
        let pathbuf_copy = pathbuf.clone();
        let rootfs_dirname = pathbuf_copy
            .file_name()
            .unwrap_or(OsStr::new("/"))
            .to_str()
            .ok_or(io::Error::other(format!(
                "unable to convert rootfs directory name (\"{:?}\") to str",
                pathbuf_copy
            )))?;

        // Traverse each directory and file within the root directory tree. If a directory is not
        // found within the denylist, add it to the archive.
        for entry in fs::read_dir(pathbuf)? {
            let entry = entry?;
            let filetype = entry.file_type()?;
            let filename = entry.file_name().into_string().map_err(|e| {
                io::Error::other(format!(
                    "unable to convert file name {:?} to String object",
                    e
                ))
            })?;

            if !ROOTFS_DIR_DENYLIST.contains(&filename.as_str()) && filename != rootfs_dirname {
                if filetype.is_dir() {
                    builder.append_dir_all(format!("rootfs/{}", filename), entry.path())?
                } else if filetype.is_file() {
                    builder.append_path_with_name(entry.path(), format!("rootfs/{}", filename))?
                }
            }
        }

        builder.into_inner()
    }

    /// Receive a 4-byte (representing an i32) return code from the enclave via vsock. This
    /// represents the return code of the application that ran within the enclave.
    fn shutdown_ret(&self, vsock_listener: VsockListener) -> Result<i32, return_code::Error> {
        let (mut vsock_stream, _vsock_addr) = vsock_listener
            .accept()
            .map_err(return_code::Error::VsockAccept)?;

        let mut buf = [0u8; 4];
        let _ = vsock_stream
            .read(&mut buf)
            .map_err(return_code::Error::VsockRead)?;

        let close_signal: u32 = 0;
        vsock_stream
            .write_all(&close_signal.to_ne_bytes())
            .map_err(return_code::Error::VsockWrite)?;

        Ok(i32::from_ne_bytes(buf))
    }

    /// Enable or disable all signals.
    fn signals(&self, enable: bool) {
        let sig = if enable {
            libc::SIG_UNBLOCK
        } else {
            libc::SIG_BLOCK
        };

        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigfillset(&mut set);
            libc::pthread_sigmask(sig, &set, std::ptr::null_mut());
        }
    }
}

/// Each service provided to an enclave is done so via vsock. Each service has a designated port
/// offset (relative to the enclave VM's CID) to connect to for service. The port number for each of
/// an enclave's services can be calculated as:
///
/// vsock port = (Enclave VM CID + vsock port offset)
#[repr(u32)]
pub enum VsockPortOffset {
    ArgsReader = 1,
    Net = 2,
    AppOutput = 3,
    ReturnCode = 4,
    SignalHandler = 5,
    // Not set by krun-nitro.
    Console = 10000,
}

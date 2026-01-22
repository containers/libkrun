// SPDX-License-Identifier: Apache-2.0

pub(crate) mod args_writer;
pub(crate) mod device;

use super::error::{
    return_code::Error as ReturnCodeListenerError, start::Error as StartError, Error,
};
use args_writer::EnclaveArgsWriter;
use device::{
    net::NetProxy, output::OutputProxy, signal_handler::SignalHandler, DeviceProxy, DeviceProxyList,
};
use nitro_enclaves::{
    launch::{ImageType, Launcher, MemoryInfo, PollTimeout, StartFlags},
    Device,
};
use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, Read},
    os::fd::RawFd,
    path::PathBuf,
};
use tar::HeaderMode;
use vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

const ROOTFS_DIR_DENYLIST: [&str; 6] = [
    "proc", // /proc.
    "run",  // /run.
    "tmp",  // /tmp.
    "dev",  // /dev.
    "sys",  // /sys.
    "usr/share/krun-nitro",
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
    // Output kernel and initramfs debug logs from enclave.
    pub debug: bool,
}

impl NitroEnclave {
    /// Run the enclave.
    pub fn run(mut self) -> Result<(), Error> {
        let rootfs_archive = self.rootfs_archive().map_err(Error::RootFsArchive)?;

        let devices = self.devices().map_err(Error::Device)?;

        let writer = EnclaveArgsWriter::new(
            &rootfs_archive,
            &self.exec_path,
            &self.exec_args,
            &self.exec_env,
            &devices,
        );

        // Disable signals to launch enclave VM.
        self.signals(false);

        let (cid, timeout) = self.start().map_err(Error::Start)?;

        writer.write_args(cid, timeout).map_err(Error::ArgsWrite)?;

        let retcode_listener = VsockListener::bind(&VsockAddr::new(
            VMADDR_CID_ANY,
            cid + (VsockPortOffset::ReturnCode as u32),
        ))
        .map_err(ReturnCodeListenerError::VsockBind)
        .map_err(Error::ReturnCodeListener)?;

        // Enable signals now that enclave VM is started.
        self.signals(true);

        devices.start(cid).map_err(Error::Device)?;

        /*
         * In debug mode, the console device doesn't shut down until the enclave
         * itself exits. Thus, libkrun will be unable to retrieve the shutdown
         * code from the enclave.
         */
        if !self.debug {
            let ret = self
                .shutdown_ret(retcode_listener)
                .map_err(Error::ReturnCodeListener)?;
            if ret != 0 {
                return Err(Error::AppReturn(ret));
            }
        }

        Ok(())
    }

    fn start(&mut self) -> Result<(u32, PollTimeout), StartError> {
        let path = env::var("KRUN_NITRO_EIF_PATH")
            .unwrap_or("/usr/share/krun-nitro/krun-nitro.eif".to_string());

        let eif = fs::read(path).map_err(StartError::EifRead)?;

        let timeout = PollTimeout::try_from((eif.as_slice(), self.mem_size_mib << 20))
            .map_err(StartError::PollTimeoutCalculate)?;

        let device = Device::open().map_err(StartError::DeviceOpen)?;

        let mut launcher = Launcher::new(&device).map_err(StartError::VmCreate)?;

        let mem = MemoryInfo::new(ImageType::Eif(&eif), self.mem_size_mib);
        launcher.set_memory(mem).map_err(StartError::VmMemorySet)?;

        for _ in 0..self.vcpus {
            launcher.add_vcpu(None).map_err(StartError::VcpuAdd)?;
        }

        let mut start_flags = StartFlags::empty();

        if self.debug {
            start_flags |= StartFlags::DEBUG;
        }

        let cid = launcher
            .start(start_flags, None)
            .map_err(StartError::VmStart)?;

        // Safe to unwrap.
        Ok((cid.try_into().unwrap(), timeout))
    }

    fn devices(&self) -> Result<DeviceProxyList, device::Error> {
        let mut proxies: Vec<Box<dyn Send + DeviceProxy>> = vec![];

        let output = OutputProxy::new(&self.output_path, self.debug)?;
        proxies.push(Box::new(output));

        if let Some(fd) = self.net_unixfd {
            let net = NetProxy::try_from(fd)?;
            proxies.push(Box::new(net));
        }

        proxies.push(Box::new(SignalHandler::new()?));

        Ok(DeviceProxyList(proxies))
    }

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

    fn shutdown_ret(&self, vsock_listener: VsockListener) -> Result<i32, ReturnCodeListenerError> {
        let (mut vsock_stream, _vsock_addr) = vsock_listener
            .accept()
            .map_err(ReturnCodeListenerError::VsockAccept)?;

        let mut buf = [0u8; 4];
        let _ = vsock_stream
            .read(&mut buf)
            .map_err(ReturnCodeListenerError::VsockRead)?;

        Ok(i32::from_ne_bytes(buf))
    }

    // Enable or disable all signals.
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

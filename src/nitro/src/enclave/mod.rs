// SPDX-License-Identifier: Apache-2.0

pub mod args_writer;
pub mod device;

use args_writer::EnclaveArgsWriter;
use device::{net::NetProxy, output::OutputProxy, DeviceProxy, DeviceProxyList};
use nitro_enclaves::{
    launch::{ImageType, Launcher, MemoryInfo, PollTimeout, StartFlags},
    Device,
};
use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, Read},
    path::PathBuf,
};
use vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

use super::error::NitroError;
use tar::HeaderMode;

type Result<T> = std::result::Result<T, NitroError>;

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
    pub net: Option<NetProxy>,
    /// Path to redirect enclave output to.
    pub output_path: PathBuf,
    // Output kernel and initramfs debug logs from enclave.
    pub debug: bool,
}

impl NitroEnclave {
    /// Run the enclave.
    pub fn run(mut self) -> Result<()> {
        let rootfs_archive = self.rootfs_archive()?;

        let devices = self.devices()?;

        let writer = EnclaveArgsWriter::new(
            &rootfs_archive,
            &self.exec_path,
            &self.exec_args,
            &self.exec_env,
            &devices,
        );

        let (cid, timeout) = self.start()?;

        writer.write_args(cid, timeout)?;

        let retcode_listener = VsockListener::bind(&VsockAddr::new(
            VMADDR_CID_ANY,
            cid + (VsockPortOffset::ReturnCode as u32),
        ))
        .unwrap();

        devices.start(cid);

        /*
         * In debug mode, the console device doesn't shut down until the enclave
         * itself exits. Thus, libkrun will be unable to retrieve the shutdown
         * code from the enclave.
         */
        if !self.debug {
            let ret = self.shutdown_ret(retcode_listener)?;
            if ret != 0 {
                return Err(NitroError::AppReturn(ret));
            }
        }

        Ok(())
    }

    fn start(&mut self) -> Result<(u32, PollTimeout)> {
        let eif = eif()?;

        let timeout = PollTimeout::try_from((eif.as_slice(), self.mem_size_mib << 20))
            .map_err(NitroError::PollTimeoutCalculate)?;

        let device = Device::open().map_err(NitroError::DeviceOpen)?;

        let mut launcher = Launcher::new(&device).map_err(NitroError::VmCreate)?;

        let mem = MemoryInfo::new(ImageType::Eif(&eif), self.mem_size_mib);
        launcher.set_memory(mem).map_err(NitroError::VmMemorySet)?;

        for _ in 0..self.vcpus {
            launcher.add_vcpu(None).map_err(NitroError::VcpuAdd)?;
        }

        let mut start_flags = StartFlags::empty();

        if self.debug {
            start_flags |= StartFlags::DEBUG;
        }

        let cid = launcher
            .start(start_flags, None)
            .map_err(NitroError::VmStart)?;

        Ok((cid.try_into().unwrap(), timeout)) // Safe to unwrap.
    }

    fn devices(&self) -> Result<DeviceProxyList> {
        let mut proxies: Vec<Box<dyn Send + DeviceProxy>> = vec![];

        let output =
            OutputProxy::new(&self.output_path, self.debug).map_err(NitroError::DeviceError)?;
        proxies.push(Box::new(output));

        if let Some(net) = self.net.clone() {
            proxies.push(Box::new(net));
        }

        Ok(DeviceProxyList(proxies))
    }

    fn rootfs_archive(&self) -> Result<Vec<u8>> {
        let mut builder = tar::Builder::new(Vec::new());

        builder.mode(HeaderMode::Deterministic);
        builder.follow_symlinks(false);

        let pathbuf = PathBuf::from(self.rootfs.clone());
        let pathbuf_copy = pathbuf.clone();
        let rootfs_dirname = pathbuf_copy
            .file_name()
            .unwrap_or(OsStr::new("/"))
            .to_str()
            .ok_or(NitroError::RootFsArchive(io::Error::other(
                "unable to convert rootfs directory name to str",
            )))?;

        for entry in fs::read_dir(pathbuf).map_err(NitroError::RootFsArchive)? {
            let entry = entry.map_err(NitroError::RootFsArchive)?;
            let filetype = entry.file_type().map_err(NitroError::RootFsArchive)?;
            let filename = entry.file_name().into_string().map_err(|_| {
                NitroError::RootFsArchive(io::Error::other(
                    "unable to convert file name to String object",
                ))
            })?;

            if !ROOTFS_DIR_DENYLIST.contains(&filename.as_str()) && filename != rootfs_dirname {
                if filetype.is_dir() {
                    builder
                        .append_dir_all(format!("rootfs/{}", filename), entry.path())
                        .map_err(NitroError::RootFsArchive)?;
                } else if filetype.is_file() {
                    builder
                        .append_path_with_name(entry.path(), format!("rootfs/{}", filename))
                        .map_err(NitroError::RootFsArchive)?;
                }
            }
        }

        builder.into_inner().map_err(NitroError::RootFsArchive)
    }

    fn shutdown_ret(&self, vsock_listener: VsockListener) -> Result<i32> {
        let (mut vsock_stream, _vsock_addr) = vsock_listener.accept().unwrap();

        let mut buf = [0u8; 4];
        let _ = vsock_stream.read(&mut buf).unwrap();

        Ok(i32::from_ne_bytes(buf))
    }
}

fn eif() -> Result<Vec<u8>> {
    let path = env::var("KRUN_NITRO_EIF_PATH")
        .unwrap_or("/usr/share/krun-nitro/krun-nitro.eif".to_string());

    let bytes = fs::read(path).map_err(NitroError::EifRead)?;

    Ok(bytes)
}

#[repr(u32)]
pub enum VsockPortOffset {
    ArgsReader = 1,
    Net = 2,
    AppOutput = 3,
    ReturnCode = 4,
    // Not set by krun-nitro.
    Console = 10000,
}

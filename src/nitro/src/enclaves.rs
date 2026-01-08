// SPDX-License-Identifier: Apache-2.0

use super::{
    args_writer::{EnclaveArg, EnclaveArgsWriter},
    error::NitroError,
    net::NetProxy,
    output::output_proxy,
};
use nitro_enclaves::{
    launch::{ImageType, Launcher, MemoryInfo, PollTimeout, StartFlags},
    Device,
};
use std::{
    env,
    ffi::OsStr,
    fs, io,
    path::PathBuf,
    thread::{self, JoinHandle},
};
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

        let argv: Vec<String> = self
            .exec_args
            .replace("\"", "")
            .split(' ')
            .map(|s| s.to_string())
            .collect();

        let envp: Vec<String> = self
            .exec_env
            .replace("\"", "")
            .split(' ')
            .map(|s| s.to_string())
            .collect();

        let mut writer = EnclaveArgsWriter::default();
        writer.args.append(&mut vec![
            EnclaveArg::RootFilesystem(rootfs_archive.as_slice()),
            EnclaveArg::ExecPath(self.exec_path.clone()),
            EnclaveArg::ExecArgv(argv),
            EnclaveArg::ExecEnvp(envp),
        ]);

        if self.debug {
            writer.args.push(EnclaveArg::Debug);
        }

        if self.net.is_some() {
            writer.args.push(EnclaveArg::NetworkProxy);
        }

        let (cid, timeout) = self.start()?;

        writer.write_args(cid, timeout)?;

        let net_proxy_thread: JoinHandle<Result<()>> = thread::spawn(move || {
            if let Some(net_proxy) = &self.net {
                net_proxy.run().map_err(NitroError::NetError)?;
            }

            Ok(())
        });

        let output_proxy_thread: JoinHandle<Result<()>> = thread::spawn(move || {
            let debug_cid = if self.debug { Some(cid) } else { None };

            output_proxy(&self.output_path, debug_cid).map_err(NitroError::OutputError)?;

            Ok(())
        });

        if let Ok(Err(err)) = net_proxy_thread.join() {
            log::error!("error with network vsock stream listener thread: {:?}", err);
            return Err(err);
        }

        if let Ok(Err(err)) = output_proxy_thread.join() {
            log::error!("error with enclave output proxy: {:?}", err);
            return Err(err);
        }

        Ok(())
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
}

fn eif() -> Result<Vec<u8>> {
    let path = env::var("KRUN_NITRO_EIF_PATH")
        .unwrap_or("/usr/share/krun-nitro/krun-nitro.eif".to_string());

    let bytes = fs::read(path).unwrap();

    Ok(bytes)
}

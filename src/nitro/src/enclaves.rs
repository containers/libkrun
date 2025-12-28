// SPDX-License-Identifier: Apache-2.0

use super::{
    args_writer::{EnclaveArg, EnclaveArgsWriter},
    error::NitroError,
    net::NetProxy,
};
use nitro_enclaves::{
    launch::{ImageType, Launcher, MemoryInfo, PollTimeout, StartFlags},
    Device,
};
use std::{env, ffi::OsStr, fs, io, path::PathBuf};
use tar::HeaderMode;

type Result<T> = std::result::Result<T, NitroError>;

const ROOTFS_DIR_DENYLIST: [&str; 5] = [
    "proc", // /proc.
    "run",  // /run.
    "tmp",  // /tmp.
    "dev",  // /dev.
    "sys",  // /sys.
];

/// Nitro Enclave data.
pub struct NitroEnclave {
    /// Path to configurable enclave image. Will default to KRUN_NITRO_ENCLAVE_EIF if one external
    /// enclave provided.
    pub _image_path: Option<PathBuf>,
    /// Amount of RAM (in MiB).
    pub mem_size_mib: usize,
    /// Number of vCPUs.
    pub vcpus: u8,
    /// Enclave rootfs.
    pub rootfs: String,
    /// Enclave start flags.
    pub start_flags: StartFlags,
    /// Execution path.
    pub exec_path: String,
    /// Execution args.
    pub exec_args: String,
    /// Execution environment.
    pub exec_env: String,
    /// Network proxy.
    pub net: Option<NetProxy>,
}

impl NitroEnclave {
    /// Run the enclave.
    pub fn run(&mut self) -> Result<u32> {
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

        if self.net.is_some() {
            writer.args.push(EnclaveArg::NetworkProxy);
        }

        let (cid, timeout) = self.start()?;

        writer.write_args(cid, timeout)?;

        match unsafe { libc::fork() } {
            0 => {
                if let Some(net_proxy) = &self.net {
                    net_proxy.run().map_err(NitroError::NetError)?;
                }

                Ok(0)
            }
            _ => Ok(cid),
        }
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

        let cid = launcher
            .start(self.start_flags, None)
            .map_err(NitroError::VmStart)?;

        Ok((cid.try_into().unwrap(), timeout)) // Safe to unwrap.
    }
}

fn eif() -> Result<Vec<u8>> {
    let path = env::var("KRUN_NITRO_EIF_PATH").unwrap_or("/usr/share/krun-nitro.eif".to_string());

    let bytes = fs::read(path).unwrap();

    Ok(bytes)
}

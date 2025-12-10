// SPDX-License-Identifier: Apache-2.0

use super::error::NitroError;
use flate2::read::GzDecoder;
use libc::c_int;
use nitro_enclaves::{
    launch::{ImageType, Launcher, MemoryInfo, PollTimeout, StartFlags},
    Device,
};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout as NixPollTimeout};
use std::{
    ffi::{CString, OsStr},
    fs,
    io::{self, Read, Write},
    os::fd::AsFd,
    path::PathBuf,
    str::FromStr,
};
use tar::{Archive, HeaderMode};
use vsock::{VsockAddr, VsockListener, VsockStream};

type Result<T> = std::result::Result<T, NitroError>;

const KRUN_NITRO_EIF_TAR: &[u8] = include_bytes!("runtime-data/eif.tar.gz");
const KRUN_NITRO_EIF_FILE_NAME: &str = "krun-nitro.eif";

const ENCLAVE_READY_VSOCK_PORT: u32 = 9000;

const VMADDR_CID_PARENT: u32 = 3;

const HEART_BEAT: u8 = 0xb7;

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
}

impl NitroEnclave {
    /// Run the enclave.
    pub fn run(&mut self) -> Result<u32> {
        let rootfs_archive = self.rootfs_archive()?;

        let (cid, mut stream) = self.start()?;

        vsock_write_bytes(&rootfs_archive, &mut stream)?;

        self.write_exec(&mut stream)?;

        Ok(cid)
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

    fn write_exec(&self, stream: &mut VsockStream) -> Result<()> {
        vsock_write_bytes(&str_cstring_bytes(&self.exec_path)?, stream)?;

        let argv: Vec<String> = self
            .exec_args
            .replace("\"", "")
            .split(' ')
            .map(|s| s.to_string())
            .collect();

        vsock_write_str_vec(&argv, stream)?;

        let envp: Vec<String> = self
            .exec_env
            .replace("\"", "")
            .split(' ')
            .map(|s| s.to_string())
            .collect();

        vsock_write_str_vec(&envp, stream)?;

        Ok(())
    }

    fn launch(&mut self, eif: &[u8]) -> Result<u32> {
        let device = Device::open().map_err(NitroError::DeviceOpen)?;

        let mut launcher = Launcher::new(&device).map_err(NitroError::VmCreate)?;

        let mem = MemoryInfo::new(ImageType::Eif(eif), self.mem_size_mib);
        launcher.set_memory(mem).map_err(NitroError::VmMemorySet)?;

        for _ in 0..self.vcpus {
            launcher.add_vcpu(None).map_err(NitroError::VcpuAdd)?;
        }

        let cid = launcher
            .start(self.start_flags, None)
            .map_err(NitroError::VmStart)?;

        Ok(cid.try_into().unwrap()) // Safe to unwrap.
    }

    fn poll(&self, listener: &VsockListener, eif: &[u8]) -> Result<()> {
        let poll_timeout = PollTimeout::try_from((eif, self.mem_size_mib << 20))
            .map_err(NitroError::PollTimeoutCalculate)?;

        let mut poll_fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
        let result = poll(
            &mut poll_fds,
            NixPollTimeout::from(c_int::from(poll_timeout) as u16),
        );

        match result {
            Ok(0) => Err(NitroError::PollNoSelectedEvents),
            Ok(x) if x > 1 => Err(NitroError::PollMoreThanOneSelectedEvent),
            _ => Ok(()),
        }
    }

    fn start(&mut self) -> Result<(u32, VsockStream)> {
        let sockaddr = VsockAddr::new(VMADDR_CID_PARENT, ENCLAVE_READY_VSOCK_PORT);
        let listener = VsockListener::bind(&sockaddr).map_err(NitroError::HeartbeatBind)?;
        let eif = eif()?;

        let cid = self.launch(&eif)?;
        self.poll(&listener, &eif)?;

        let mut stream = listener.accept().map_err(NitroError::HeartbeatAccept)?;

        if stream.1.cid() != cid {
            return Err(NitroError::HeartbeatCidMismatch);
        }

        let mut buf = [0u8];
        let bytes = stream.0.read(&mut buf).map_err(NitroError::HeartbeatRead)?;

        if bytes != 1 || buf[0] != HEART_BEAT {
            return Err(NitroError::EnclaveHeartbeatNotDetected);
        }

        stream
            .0
            .write_all(&buf)
            .map_err(NitroError::HeartbeatWrite)?;

        Ok((cid, stream.0))
    }
}

fn str_cstring_bytes(string: &str) -> Result<Vec<u8>> {
    let bytes = Vec::from(
        CString::from_str(string)
            .map_err(NitroError::CStringConversion)?
            .as_bytes_with_nul(),
    );

    Ok(bytes)
}

fn vsock_write_str_vec(vec: &Vec<String>, stream: &mut VsockStream) -> Result<()> {
    let len: u32 = vec
        .len()
        .try_into()
        .or(Err(NitroError::VsockBytesTooLarge))?;

    stream
        .write_all(&len.to_ne_bytes())
        .map_err(NitroError::VsockBytesLenWrite)?;

    for string in vec {
        vsock_write_bytes(&str_cstring_bytes(string)?, stream)?;
    }

    Ok(())
}

fn vsock_write_bytes(bytes: &[u8], stream: &mut VsockStream) -> Result<()> {
    let len: u32 = bytes
        .len()
        .try_into()
        .or(Err(NitroError::VsockBytesTooLarge))?;

    stream
        .write_all(&len.to_ne_bytes())
        .map_err(NitroError::VsockBytesLenWrite)?;

    stream
        .write_all(bytes)
        .map_err(NitroError::VsockBytesWrite)?;

    Ok(())
}

fn eif() -> Result<Vec<u8>> {
    let gz = GzDecoder::new(KRUN_NITRO_EIF_TAR);
    let mut archive = Archive::new(gz);

    let mut buf = Vec::new();

    for entry_result in archive.entries().map_err(NitroError::EifTarExtract)? {
        let mut entry = entry_result.map_err(NitroError::EifTarExtract)?;

        let path = entry.path().map_err(NitroError::EifTarExtract)?;
        let path_str = path.to_string_lossy();

        if path_str == KRUN_NITRO_EIF_FILE_NAME {
            entry
                .read_to_end(&mut buf)
                .map_err(NitroError::EifTarExtract)?;
            break;
        }
    }

    Ok(buf)
}

// SPDX-License-Identifier: Apache-2.0

use super::error::NitroError;
use libc::c_int;
use nitro_enclaves::{
    launch::{ImageType, Launcher, MemoryInfo, PollTimeout, StartFlags},
    Device,
};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout as NixPollTimeout};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::AsFd,
    path::PathBuf,
};
use vsock::{VsockAddr, VsockListener, VsockStream};

type Result<T> = std::result::Result<T, NitroError>;

const ENCLAVE_READY_VSOCK_PORT: u32 = 9000;

const VMADDR_CID_PARENT: u32 = 3;

const HEART_BEAT: u8 = 0xb7;

/// Nitro Enclave data.
pub struct NitroEnclave {
    /// Enclave image.
    pub image: File,
    /// Amount of RAM (in MiB).
    pub mem_size_mib: usize,
    /// Number of vCPUs.
    pub vcpus: u8,
    /// Enclave rootfs.
    pub rootfs: PathBuf,
    /// Enclave start flags.
    pub start_flags: StartFlags,
}

impl NitroEnclave {
    /// Run the enclave.
    pub fn run(&mut self) -> Result<u32> {
        let _rootfs_archive = self.rootfs_archive()?;

        let (cid, _stream) = self.start()?;

        Ok(cid)
    }

    fn rootfs_archive(&self) -> Result<Vec<u8>> {
        let mut builder = tar::Builder::new(Vec::new());

        builder
            .append_dir_all("rootfs", self.rootfs.clone())
            .unwrap();

        builder.into_inner().map_err(NitroError::RootFsArchive)
    }

    fn launch(&mut self) -> Result<u32> {
        let device = Device::open().map_err(NitroError::DeviceOpen)?;

        let mut launcher = Launcher::new(&device).map_err(NitroError::VmCreate)?;

        let mem = MemoryInfo::new(ImageType::Eif(&mut self.image), self.mem_size_mib);
        launcher.set_memory(mem).map_err(NitroError::VmMemorySet)?;

        for _ in 0..self.vcpus {
            launcher.add_vcpu(None).map_err(NitroError::VcpuAdd)?;
        }

        let cid = launcher
            .start(self.start_flags, None)
            .map_err(NitroError::VmStart)?;

        Ok(cid.try_into().unwrap()) // Safe to unwrap.
    }

    fn poll(&self, listener: &VsockListener) -> Result<()> {
        let poll_timeout = PollTimeout::try_from((&self.image, self.mem_size_mib << 20))
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

        let cid = self.launch()?;
        self.poll(&listener)?;

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

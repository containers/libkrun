// SPDX-License-Identifier: Apache-2.0

use super::error::NitroError;
use nitro_enclaves::{
    launch::{ImageType, Launcher, MemoryInfo, PollTimeout, StartFlags},
    Device,
};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout as NixPollTimeout};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::AsFd,
};
use vsock::{VsockAddr, VsockListener};

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
    /// Enclave start flags.
    pub start_flags: StartFlags,
}

impl NitroEnclave {
    /// Run the enclave.
    pub fn run(&mut self) -> Result<u32> {
        let device = Device::open().map_err(NitroError::DeviceOpen)?;

        let mut launcher = Launcher::new(&device).map_err(NitroError::VmCreate)?;

        let mem = MemoryInfo::new(ImageType::Eif(&mut self.image), self.mem_size_mib);
        launcher.set_memory(mem).map_err(NitroError::VmMemorySet)?;

        for _ in 0..self.vcpus {
            launcher.add_vcpu(None).map_err(NitroError::VcpuAdd)?;
        }

        let sockaddr = VsockAddr::new(VMADDR_CID_PARENT, ENCLAVE_READY_VSOCK_PORT);
        let listener = VsockListener::bind(&sockaddr).map_err(NitroError::HeartbeatBind)?;

        let cid = launcher
            .start(self.start_flags, None)
            .map_err(NitroError::VmStart)?;

        // Safe to unwrap.
        let cid: u32 = cid.try_into().unwrap();

        let poll_timeout = PollTimeout::try_from((&self.image, self.mem_size_mib << 20))
            .map_err(NitroError::PollTimeoutCalculate)?;

        enclave_check(listener, poll_timeout.into(), cid)?;

        Ok(cid)
    }
}

fn enclave_check(listener: VsockListener, poll_timeout_ms: libc::c_int, cid: u32) -> Result<()> {
    let mut poll_fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
    let result = poll(&mut poll_fds, NixPollTimeout::from(poll_timeout_ms as u16));
    if result == Ok(0) {
        return Err(NitroError::PollNoSelectedEvents);
    } else if result != Ok(1) {
        return Err(NitroError::PollMoreThanOneSelectedEvent);
    }

    let mut stream = listener.accept().map_err(NitroError::HeartbeatAccept)?;

    let mut buf = [0u8];
    let bytes = stream.0.read(&mut buf).map_err(NitroError::HeartbeatRead)?;

    if bytes != 1 || buf[0] != HEART_BEAT {
        return Err(NitroError::EnclaveHeartbeatNotDetected);
    }

    stream
        .0
        .write_all(&buf)
        .map_err(NitroError::HeartbeatWrite)?;

    if stream.1.cid() != cid {
        return Err(NitroError::HeartbeatCidMismatch);
    }

    Ok(())
}

// SPDX-License-Identifier: Apache-2.0

mod error;

use error::NitroError;
use nitro_enclaves::{
    launch::{ImageType, Launcher, MemoryInfo, PollTimeout, StartFlags},
    Device,
};
use nix::{
    poll::{poll, PollFd, PollFlags},
    sys::{
        socket::{connect, socket, AddressFamily, SockFlag, SockType, VsockAddr as NixVsockAddr},
        time::{TimeVal, TimeValLike},
    },
    unistd::read,
};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, RawFd},
};
use vsock::{VsockAddr, VsockListener};

type Result<T> = std::result::Result<T, NitroError>;

const ENCLAVE_READY_VSOCK_PORT: u32 = 9000;
const CID_TO_CONSOLE_PORT_OFFSET: u32 = 10000;

const VMADDR_CID_PARENT: u32 = 3;
const VMADDR_CID_HYPERVISOR: u32 = 0;

const SO_VM_SOCKETS_CONNECT_TIMEOUT: i32 = 6;

const HEART_BEAT: u8 = 0xb7;

/// Nitro Enclave data.
#[derive(Debug)]
pub struct NitroEnclave {
    /// Enclave image.
    pub image: File,
    /// Amount of RAM (in MiB).
    pub mem_size_mib: usize,
    /// Number of vCPUs.
    pub vcpus: u8,
}

impl NitroEnclave {
    /// Run the enclave.
    pub fn run(&mut self) -> Result<()> {
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
            .start(StartFlags::DEBUG, None)
            .map_err(NitroError::VmStart)?;

        // Safe to unwrap.
        let cid: u32 = cid.try_into().unwrap();

        let poll_timeout = PollTimeout::try_from((&self.image, self.mem_size_mib << 20))
            .map_err(NitroError::PollTimeoutCalculate)?;

        enclave_check(listener, poll_timeout.into(), cid)?;

        listen(VMADDR_CID_HYPERVISOR, cid + CID_TO_CONSOLE_PORT_OFFSET)?;

        Ok(())
    }
}

fn enclave_check(listener: VsockListener, poll_timeout_ms: libc::c_int, cid: u32) -> Result<()> {
    let mut poll_fds = [PollFd::new(listener.as_raw_fd(), PollFlags::POLLIN)];
    let result = poll(&mut poll_fds, poll_timeout_ms);
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

fn listen(cid: u32, port: u32) -> Result<()> {
    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|_| NitroError::VsockCreate)?;

    let sockaddr = NixVsockAddr::new(cid, port);

    vsock_timeout(socket_fd)?;

    connect(socket_fd, &sockaddr).map_err(|_| NitroError::VsockConnect)?;

    let mut buf = [0u8; 512];
    loop {
        // Read debug output from vsock.
        let ret = read(socket_fd, &mut buf);
        let Ok(sz) = ret else {
            break;
        };
        if sz != 0 {
            let msg = String::from_utf8(buf[..sz].to_vec()).unwrap();
            print!("{}", msg);
        } else {
            break;
        }
    }

    Ok(())
}

fn vsock_timeout(socket_fd: RawFd) -> Result<()> {
    // Set the timeout to 20 seconds.
    let timeval = TimeVal::milliseconds(20000);

    let ret = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::AF_VSOCK,
            SO_VM_SOCKETS_CONNECT_TIMEOUT,
            &timeval as *const _ as *const libc::c_void,
            size_of::<TimeVal>() as u32,
        )
    };

    if ret != 0 {
        return Err(NitroError::VsockSetTimeout);
    }

    Ok(())
}

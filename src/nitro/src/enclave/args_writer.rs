// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{device::DeviceProxyList, VsockPortOffset};
use libc::c_int;
use nitro_enclaves::launch::PollTimeout;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout as NixPollTimeout};
use std::{
    ffi::{self, CString},
    fmt,
    io::{self, Read, Write},
    num::TryFromIntError,
    os::fd::AsFd,
    str::FromStr,
};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

const ENCLAVE_VSOCK_LAUNCH_ARGS_READY: u8 = 0xb7;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Default)]
pub struct EnclaveArgsWriter<'a> {
    pub args: Vec<EnclaveArg<'a>>,
}

impl<'a> EnclaveArgsWriter<'a> {
    pub fn new(
        rootfs_archive: &'a [u8],
        exec_path: &str,
        argv_str: &str,
        envp_str: &str,
        devices: &'a DeviceProxyList,
    ) -> Self {
        let mut args: Vec<EnclaveArg<'a>> = Vec::new();

        let argv: Vec<String> = argv_str
            .replace("\"", "")
            .split(' ')
            .map(|s| s.to_string())
            .collect();

        let envp: Vec<String> = envp_str
            .replace("\"", "")
            .split(' ')
            .map(|s| s.to_string())
            .collect();

        args.append(&mut vec![
            EnclaveArg::RootFilesystem(rootfs_archive),
            EnclaveArg::ExecPath(exec_path.to_string()),
            EnclaveArg::ExecArgv(argv),
            EnclaveArg::ExecEnvp(envp),
        ]);

        for device in &devices.0 {
            if let Some(arg) = device.arg() {
                args.push(arg);
            }
        }

        Self { args }
    }
    pub fn write_args(&self, cid: u32, timeout: PollTimeout) -> Result<()> {
        let listener = VsockListener::bind(&VsockAddr::new(
            VMADDR_CID_ANY,
            cid + (VsockPortOffset::ArgsReader as u32),
        ))
        .map_err(Error::VsockBind)?;

        self.poll(&listener, timeout)?;

        let mut stream = listener.accept().map_err(Error::VsockAccept)?;

        if stream.1.cid() != cid {
            return Err(Error::VsockCidMismatch);
        }

        let mut buf = [0u8];
        let bytes = stream.0.read(&mut buf).map_err(Error::VsockRead)?;

        if bytes != 1 || buf[0] != ENCLAVE_VSOCK_LAUNCH_ARGS_READY {
            return Err(Error::ReadySignalNotDetected);
        }

        stream.0.write_all(&buf).map_err(Error::VsockWrite)?;

        for arg in &self.args {
            arg.write(&mut stream.0)?;
        }

        // Notify the enclave that the args are finished being written.
        let finished = EnclaveArg::Finished;
        finished.write(&mut stream.0)?;

        Ok(())
    }

    fn poll(&self, listener: &VsockListener, timeout: PollTimeout) -> Result<()> {
        let mut poll_fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
        let result = poll(
            &mut poll_fds,
            NixPollTimeout::from(c_int::from(timeout) as u16),
        );

        match result {
            Ok(0) => Err(Error::PollNoEvents),
            Ok(x) if x > 1 => Err(Error::PollMoreThanOneSelectedEvent),
            _ => Ok(()),
        }
    }
}

#[derive(Debug)]
pub enum EnclaveArg<'a> {
    RootFilesystem(&'a [u8]),
    ExecPath(String),
    ExecArgv(Vec<String>),
    ExecEnvp(Vec<String>),
    NetworkProxy,
    Debug,
    Finished,
}

impl From<&EnclaveArg<'_>> for u8 {
    fn from(arg: &EnclaveArg) -> u8 {
        match arg {
            EnclaveArg::RootFilesystem(_) => 0,
            EnclaveArg::ExecPath(_) => 1,
            EnclaveArg::ExecArgv(_) => 2,
            EnclaveArg::ExecEnvp(_) => 3,
            EnclaveArg::NetworkProxy => 4,
            EnclaveArg::Debug => 5,

            EnclaveArg::Finished => 255,
        }
    }
}

impl EnclaveArg<'_> {
    fn write(&self, vsock: &mut VsockStream) -> Result<()> {
        let id: [u8; 1] = [self.into()];

        vsock.write_all(&id).map_err(Error::VsockWrite)?;

        match self {
            Self::RootFilesystem(buf) => {
                let len: u64 = buf.len().try_into().map_err(Error::VsockBufferLenConvert)?;

                vsock
                    .write_all(&len.to_ne_bytes())
                    .map_err(Error::VsockWrite)?;

                vsock.write_all(buf).map_err(Error::VsockWrite)?;
            }
            Self::ExecArgv(vec) | Self::ExecEnvp(vec) => {
                let len: u64 = vec.len().try_into().map_err(Error::VsockBufferLenConvert)?;

                vsock
                    .write_all(&len.to_ne_bytes())
                    .map_err(Error::VsockWrite)?;

                for string in vec {
                    let bytes = Vec::from(
                        CString::from_str(string)
                            .map_err(Error::CStringConvert)?
                            .as_bytes_with_nul(),
                    );

                    let len: u64 = bytes
                        .len()
                        .try_into()
                        .map_err(Error::VsockBufferLenConvert)?;

                    vsock
                        .write_all(&len.to_ne_bytes())
                        .map_err(Error::VsockWrite)?;

                    vsock.write_all(&bytes).map_err(Error::VsockWrite)?;
                }
            }
            Self::ExecPath(buf) => {
                let bytes = Vec::from(
                    CString::from_str(buf)
                        .map_err(Error::CStringConvert)?
                        .as_bytes_with_nul(),
                );
                let len: u64 = bytes
                    .len()
                    .try_into()
                    .map_err(Error::VsockBufferLenConvert)?;

                vsock
                    .write_all(&len.to_ne_bytes())
                    .map_err(Error::VsockWrite)?;

                vsock.write_all(&bytes).map_err(Error::VsockWrite)?;
            }
            _ => (),
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    CStringConvert(ffi::NulError),
    PollNoEvents,
    PollMoreThanOneSelectedEvent,
    ReadySignalNotDetected,
    VsockAccept(io::Error),
    VsockBind(io::Error),
    VsockBufferLenConvert(TryFromIntError),
    VsockCidMismatch,
    VsockRead(io::Error),
    VsockWrite(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::CStringConvert(e) => format!("unable to convert string to CString: {e}"),
            Self::PollNoEvents => "no events on vsock detected".to_string(),
            Self::PollMoreThanOneSelectedEvent => {
                "more than one event on vsock detected".to_string()
            }
            Self::ReadySignalNotDetected => "ready signal not detected".to_string(),
            Self::VsockAccept(e) => format!("unable to accept vsock connection: {e}"),
            Self::VsockBind(e) => format!("unable to bind to vsock: {e}"),
            Self::VsockBufferLenConvert(e) => {
                format!("unable to convert vsock buffer size to u64: {e}")
            }
            Self::VsockCidMismatch => "CID mismatch on vsock".to_string(),
            Self::VsockRead(e) => format!("unable to read from vsock: {e}"),
            Self::VsockWrite(e) => format!("unable to write to vsock: {e}"),
        };

        write!(f, "{}", msg)
    }
}

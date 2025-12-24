// SPDX-License-Identifier: Apache-2.0

use crate::error::NitroError;
use libc::c_int;
use nitro_enclaves::launch::PollTimeout;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout as NixPollTimeout};
use std::{
    ffi::CString,
    io::{Read, Write},
    os::fd::AsFd,
    str::FromStr,
};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

const ENCLAVE_VSOCK_PORT_LAUNCH_ARGS: u32 = 9000;
const ENCLAVE_VSOCK_LAUNCH_ARGS_READY: u8 = 0xb7;

type Result<T> = std::result::Result<T, NitroError>;

#[derive(Debug)]
pub struct EnclaveArgsWriter<'a> {
    vsock_addr: VsockAddr,
    pub args: Vec<EnclaveArg<'a>>,
}

impl Default for EnclaveArgsWriter<'_> {
    fn default() -> Self {
        Self {
            vsock_addr: VsockAddr::new(VMADDR_CID_ANY, ENCLAVE_VSOCK_PORT_LAUNCH_ARGS),
            args: Vec::new(),
        }
    }
}

impl EnclaveArgsWriter<'_> {
    pub fn write_args(&self, cid: u32, timeout: PollTimeout) -> Result<()> {
        let listener = VsockListener::bind(&self.vsock_addr).unwrap();
        self.poll(&listener, timeout)?;

        let mut stream = listener.accept().unwrap();

        if stream.1.cid() != cid {
            return Err(NitroError::HeartbeatCidMismatch);
        }

        let mut buf = [0u8];
        let bytes = stream.0.read(&mut buf).map_err(NitroError::HeartbeatRead)?;

        if bytes != 1 || buf[0] != ENCLAVE_VSOCK_LAUNCH_ARGS_READY {
            return Err(NitroError::EnclaveHeartbeatNotDetected);
        }

        stream
            .0
            .write_all(&buf)
            .map_err(NitroError::HeartbeatWrite)?;

        for arg in &self.args {
            arg.write(&mut stream.0)?;
        }

        Ok(())
    }

    fn poll(&self, listener: &VsockListener, timeout: PollTimeout) -> Result<()> {
        let mut poll_fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
        let result = poll(
            &mut poll_fds,
            NixPollTimeout::from(c_int::from(timeout) as u16),
        );

        match result {
            Ok(0) => Err(NitroError::PollNoSelectedEvents),
            Ok(x) if x > 1 => Err(NitroError::PollMoreThanOneSelectedEvent),
            _ => Ok(()),
        }
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum EnclaveArg<'a> {
    RootFilesystem(&'a [u8]),
    ExecPath(String),
    ExecArgv(Vec<String>),
    ExecEnvp(Vec<String>),
}

impl EnclaveArg<'_> {
    fn write(&self, vsock: &mut VsockStream) -> Result<()> {
        match self {
            Self::RootFilesystem(buf) => {
                let len: u32 = buf.len().try_into().unwrap();

                vsock.write_all(&len.to_ne_bytes()).unwrap();

                vsock.write_all(buf).unwrap();
            }
            Self::ExecArgv(vec) | Self::ExecEnvp(vec) => {
                let len: u32 = vec.len().try_into().unwrap();

                vsock.write_all(&len.to_ne_bytes()).unwrap();

                for string in vec {
                    let bytes = Vec::from(CString::from_str(string).unwrap().as_bytes_with_nul());

                    let len: u32 = bytes.len().try_into().unwrap();

                    vsock.write_all(&len.to_ne_bytes()).unwrap();

                    vsock.write_all(&bytes).unwrap();
                }
            }
            Self::ExecPath(buf) => {
                let bytes = Vec::from(CString::from_str(buf).unwrap().as_bytes_with_nul());
                let len: u32 = bytes.len().try_into().unwrap();

                vsock.write_all(&len.to_ne_bytes()).unwrap();

                vsock.write_all(&bytes).unwrap();
            }
        }

        Ok(())
    }
}

// SPDX-License-Identifier: Apache-2.0

mod devices;

pub use devices::*;

use crate::args_writer::EnclaveArg;
use std::{fmt, io};

type Result<T> = std::result::Result<T, Error>;

pub trait DeviceProxy {
    fn enclave_arg(&self) -> Option<EnclaveArg<'_>>;
    fn vsock_port_offset(&self) -> VsockPortOffset;
    fn start(&mut self, cid: u32) -> Result<()> {
        let port = cid + (self.vsock_port_offset() as u32);

        self._start(port)
    }
    fn _start(&mut self, vsock_port: u32) -> Result<()>;
}

pub struct DeviceProxyList(pub Vec<Box<dyn DeviceProxy>>);

#[repr(u32)]
pub enum VsockPortOffset {
    ArgsReader = 1,
    Net = 2,
    AppOutput = 3,

    // Not set by krun-nitro.
    Console = 10000,
}

#[derive(Debug)]
pub enum Error {
    FileOpen(io::Error),
    FileWrite(io::Error),
    InvalidNetInterface,
    UnixClone(io::Error),
    UnixWrite(io::Error),
    VsockAccept(io::Error),
    VsockBind(io::Error),
    VsockClone(io::Error),
    VsockConnect(io::Error),
    VsockRead(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::FileOpen(cause) => format!("unable to open file: {:?}", cause),
            Self::FileWrite(cause) => {
                format!("unable to write buffer to output file: {:?}", cause)
            }
            Self::InvalidNetInterface => {
                "invalid network proxy interface, must supply unix stream file descriptor"
                    .to_string()
            }
            Self::UnixClone(cause) => format!("unable to clone unix stream: {:?}", cause),
            Self::UnixWrite(cause) => format!("unable to write to unix stream: {:?}", cause),
            Self::VsockAccept(cause) => format!(
                "unable to accept connection from enclave vsock: {:?}",
                cause
            ),
            Self::VsockBind(cause) => {
                format!("unable to bind to enclave vsock: {:?}", cause)
            }
            Self::VsockConnect(cause) => format!("uanble to connect to enclave vsock: {:?}", cause),
            Self::VsockClone(cause) => format!("unable to clone enclave vsock: {:?}", cause),
            Self::VsockRead(cause) => {
                format!("unable to read from enclave ovsock: {:?}", cause)
            }
        };

        write!(f, "{}", msg)
    }
}

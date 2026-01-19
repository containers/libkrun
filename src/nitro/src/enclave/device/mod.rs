// SPDX-License-Identifier: Apache-2.0

mod devices;

pub use devices::*;

use crate::enclave::{args_writer::EnclaveArg, VsockPortOffset};
use std::{
    fmt, io,
    thread::{self, JoinHandle},
};

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

pub struct DeviceProxyList(pub Vec<Box<dyn Send + DeviceProxy>>);

impl DeviceProxyList {
    pub fn start(self, cid: u32) {
        let mut handles: Vec<JoinHandle<Result<()>>> = Vec::new();

        for mut device in self.0 {
            let handle: JoinHandle<Result<()>> = thread::spawn(move || {
                device.start(cid)?;

                Ok(())
            });

            handles.push(handle);
        }

        for handle in handles.into_iter() {
            let res = handle.join().unwrap();
            if let Err(err) = res {
                log::error!("error running enclave device proxy: {:?}", err);
            }
        }
    }
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
    VsockWrite(io::Error),
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
                format!("unable to read from enclave vsock: {:?}", cause)
            }
            Self::VsockWrite(cause) => format!("unable to write to enclave vsock: {:?}", cause),
        };

        write!(f, "{}", msg)
    }
}

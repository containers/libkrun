// SPDX-License-Identifier: Apache-2.0

mod devices;

pub use devices::*;

use crate::enclave::{args_writer::EnclaveArg, VsockPortOffset};
use std::{
    fmt, io,
    sync::mpsc,
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
    ShutdownSignalReceive(mpsc::RecvTimeoutError),
    SignalRegister(io::Error),
    UnixClone(io::Error),
    UnixRead(io::Error),
    UnixReadTimeoutSet(io::Error),
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
            Self::FileOpen(e) => format!("unable to open file: {e}"),
            Self::FileWrite(e) => format!("unable to write buffer to output file: {e}"),
            Self::ShutdownSignalReceive(e) => {
                format!("error while receiving read proxy shutdown signal: {e}")
            }
            Self::SignalRegister(e) => {
                format!("unable to register signal in signal handler proxy: {e}")
            }
            Self::InvalidNetInterface => {
                "invalid network proxy interface, must supply UNIX stream file descriptor"
                    .to_string()
            }
            Self::UnixClone(e) => format!("unable to clone unix stream: {e}"),
            Self::UnixRead(e) => format!("unable to read from unix stream: {e}"),
            Self::UnixReadTimeoutSet(e) => {
                format!("unable to set read timeout for unix stream: {e}")
            }
            Self::UnixWrite(e) => format!("unable to write to unix stream: {e}"),
            Self::VsockAccept(e) => format!("unable to accept connection from vsock: {e}"),
            Self::VsockBind(e) => format!("unable to bind to vsock: {e}"),
            Self::VsockConnect(e) => format!("unable to connect to vsock: {e}"),
            Self::VsockClone(e) => format!("unable to clone vsock: {e}"),
            Self::VsockRead(e) => format!("unable to read from vsock: {e}"),
            Self::VsockWrite(e) => format!("unable to write to vsock: {e}"),
        };

        write!(f, "{}", msg)
    }
}

// SPDX-License-Identifier: Apache-2.0

mod proxies;

pub use proxies::*;

use crate::enclave::args_writer::EnclaveArg;
use std::{
    fmt, io,
    sync::mpsc::{self, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::Duration,
};
use vsock::*;

type Result<T> = std::result::Result<T, Error>;

pub trait DeviceProxy: Send {
    fn arg(&self) -> Option<EnclaveArg<'_>>;
    fn clone(&self) -> Result<Option<Box<dyn DeviceProxy>>>;
    fn rcv(&mut self, vsock: &mut VsockStream) -> Result<usize>;
    fn send(&mut self, vsock: &mut VsockStream) -> Result<usize>;
    fn vsock(&self, cid: u32) -> Result<VsockStream>;
}

pub struct DeviceProxyList(pub Vec<Box<dyn Send + DeviceProxy>>);

impl DeviceProxyList {
    pub fn run(self, cid: u32) -> Result<()> {
        let mut handles: Vec<JoinHandle<Result<()>>> = Vec::new();

        for mut proxy in self.0 {
            let mut vsock_rcv = proxy.vsock(cid)?;

            let handle: JoinHandle<Result<()>> = thread::spawn(move || {
                let clone = proxy.clone()?;
                let mut vsock_send = vsock_rcv.try_clone().map_err(Error::VsockClone)?;

                let (tx, rx) = mpsc::channel::<()>();

                let rcv: JoinHandle<Result<()>> = thread::spawn(move || loop {
                    match proxy.rcv(&mut vsock_rcv) {
                        Ok(0) => {
                            let _ = tx.send(());
                            return Ok(());
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            let _ = tx.send(());
                            return Err(e);
                        }
                    }
                });

                let send: JoinHandle<Result<()>> = thread::spawn(move || {
                    if let Some(mut sender) = clone {
                        loop {
                            let size = sender.send(&mut vsock_send)?;
                            if size == 0 {
                                match rx.recv_timeout(Duration::from_micros(500)) {
                                    Ok(_) => break,
                                    Err(e) => {
                                        if e == RecvTimeoutError::Timeout {
                                            continue;
                                        } else {
                                            return Err(Error::ShutdownSignalReceive(e))?;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Ok(())
                });

                if let Ok(Err(e)) = rcv.join() {
                    log::error!("error in device proxy receive thread: {e}");
                }

                if let Ok(Err(e)) = send.join() {
                    log::error!("error in device proxy send thread: {e}");
                }

                Ok(())
            });

            handles.push(handle);
        }

        for handle in handles.into_iter() {
            let res = handle.join();
            if let Ok(Err(err)) = res {
                log::error!("error running enclave device proxy: {:?}", err);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    FileOpen(io::Error),
    FileWrite(io::Error),
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

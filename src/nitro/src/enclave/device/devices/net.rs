// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{
    args_writer::EnclaveArg,
    device::{DeviceProxy, Error, Result},
    VsockPortOffset,
};
use devices::virtio::{net::device::VirtioNetBackend, Net};
use std::{
    io::{ErrorKind, Read, Write},
    os::{
        fd::{FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
    sync::mpsc::{self, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::Duration,
};
use vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

#[derive(Clone)]
pub struct NetProxy {
    fd: RawFd,
}

impl TryFrom<&Net> for NetProxy {
    type Error = Error;

    fn try_from(net: &Net) -> Result<Self> {
        let fd = match net.cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => RawFd::from(fd),
            _ => return Err(Error::InvalidNetInterface),
        };

        Ok(Self { fd })
    }
}

impl DeviceProxy for NetProxy {
    fn vsock_port_offset(&self) -> VsockPortOffset {
        VsockPortOffset::Net
    }

    #[allow(unreachable_code)]
    fn _start(&mut self, vsock_port: u32) -> Result<()> {
        let vsock_listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, vsock_port))
            .map_err(Error::VsockBind)?;

        let mut vsock_stream = vsock_listener.accept().map_err(Error::VsockAccept)?;

        let mut vsock_stream_clone = vsock_stream.0.try_clone().map_err(Error::VsockClone)?;

        let unix_stream = unsafe { UnixStream::from(OwnedFd::from_raw_fd(self.fd)) };
        let mut unix_stream_clone_write = unix_stream.try_clone().map_err(Error::UnixClone)?;

        let (tx, rx) = mpsc::channel::<()>();

        // vsock
        let vsock_thread: JoinHandle<Result<()>> = thread::spawn(move || {
            let mut vsock_buf = [0u8; 1500];
            loop {
                let size = vsock_stream_clone
                    .read(&mut vsock_buf)
                    .map_err(Error::VsockRead)?;
                if size > 0 {
                    unix_stream_clone_write
                        .write_all(&vsock_buf[..size])
                        .map_err(Error::UnixWrite)?;
                } else {
                    tx.send(()).unwrap();
                    break;
                }
            }

            Ok(())
        });

        let mut unix_stream_clone_read = unix_stream.try_clone().unwrap();
        unix_stream_clone_read
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        // Unix
        let unix_thread: JoinHandle<Result<()>> = thread::spawn(move || {
            let mut unix_buf = [0u8; 1500];
            loop {
                match unix_stream_clone_read.read(&mut unix_buf) {
                    Ok(size) => {
                        if size > 0 {
                            if vsock_stream.0.write_all(&unix_buf[..size]).is_err() {
                                continue;
                            }
                        } else {
                            break;
                        }
                    }
                    Err(ref e)
                        if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock =>
                    {
                        match rx.recv_timeout(Duration::from_micros(500)) {
                            Ok(_) => break,
                            Err(e) => {
                                if e == RecvTimeoutError::Timeout {
                                    continue;
                                } else {
                                    panic!();
                                }
                            }
                        }
                    }
                    Err(_) => panic!(),
                }
            }

            Ok(())
        });

        if let Ok(Err(err)) = vsock_thread.join() {
            log::error!("error with network vsock stream listener thread: {:?}", err);
            return Err(err);
        }

        if let Ok(Err(err)) = unix_thread.join() {
            log::error!("error with network UNIX stream listener thread: {:?}", err);
            return Err(err);
        }

        Ok(())
    }

    fn enclave_arg(&self) -> Option<EnclaveArg<'_>> {
        Some(EnclaveArg::NetworkProxy)
    }
}

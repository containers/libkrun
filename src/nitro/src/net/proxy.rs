// SPDX-License-Identifier: Apache-2.0

use super::error::Error;
use crate::enclaves::VsockPortOffset;
use devices::virtio::{net::device::VirtioNetBackend, Net};
use std::{
    io::{ErrorKind, Read, Write},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::mpsc::{self, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::Duration,
};
use vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

type Result<T> = std::result::Result<T, Error>;

pub struct NetProxy {
    unix_stream: UnixStream,
}

impl TryFrom<&Net> for NetProxy {
    type Error = Error;

    fn try_from(net: &Net) -> Result<Self> {
        let unix_stream = match net.cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => unsafe {
                UnixStream::from(OwnedFd::from_raw_fd(fd))
            },
            _ => return Err(Error::InvalidInterface),
        };

        Ok(Self { unix_stream })
    }
}

impl NetProxy {
    #[allow(unreachable_code)]
    pub fn run(&self, cid: u32) -> Result<()> {
        let vsock_listener = VsockListener::bind(&VsockAddr::new(
            VMADDR_CID_ANY,
            cid + (VsockPortOffset::Net as u32),
        ))
        .map_err(Error::VsockBind)?;

        let mut vsock_stream = vsock_listener.accept().map_err(Error::VsockAccept)?;

        let mut vsock_stream_clone = vsock_stream.0.try_clone().map_err(Error::VsockClone)?;
        let mut unix_stream_clone_write = self.unix_stream.try_clone().map_err(Error::UnixClone)?;

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

        let mut unix_stream_clone_read = self.unix_stream.try_clone().unwrap();
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
}

// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{
    args_writer::EnclaveArg,
    device::{DeviceProxy, Error, Result},
    VsockPortOffset,
};
use std::{
    io::{ErrorKind, Read, Write},
    os::{
        fd::{FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
    time::Duration,
};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

pub struct NetProxy {
    buf: [u8; 1500],
    unix: UnixStream,
}

impl TryFrom<RawFd> for NetProxy {
    type Error = Error;

    fn try_from(fd: RawFd) -> Result<Self> {
        let buf = [0u8; 1500];

        let unix = unsafe { UnixStream::from(OwnedFd::from_raw_fd(fd)) };
        unix.set_read_timeout(Some(Duration::from_millis(250)))
            .map_err(Error::UnixReadTimeoutSet)?;

        Ok(Self { buf, unix })
    }
}

impl DeviceProxy for NetProxy {
    fn arg(&self) -> Option<EnclaveArg<'_>> {
        Some(EnclaveArg::NetworkProxy)
    }
    fn clone(&self) -> Result<Option<Box<dyn DeviceProxy>>> {
        let unix = self.unix.try_clone().map_err(Error::UnixClone)?;

        Ok(Some(Box::new(Self {
            buf: self.buf,
            unix,
        })))
    }
    fn rcv(&mut self, vsock: &mut VsockStream) -> Result<usize> {
        let size = vsock.read(&mut self.buf).map_err(Error::VsockRead)?;
        if size > 0 {
            self.unix
                .write_all(&self.buf[..size])
                .map_err(Error::UnixWrite)?;
        }

        Ok(size)
    }
    fn send(&mut self, vsock: &mut VsockStream) -> Result<usize> {
        match self.unix.read(&mut self.buf) {
            Ok(size) => {
                if size > 0 {
                    let _ = vsock.write_all(&self.buf[..size]);
                }

                Ok(size)
            }
            Err(ref e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                Ok(0)
            }
            Err(e) => Err(Error::UnixRead(e)),
        }
    }

    fn vsock(&self, cid: u32) -> Result<VsockStream> {
        let port = cid + (VsockPortOffset::Net as u32);

        let listener =
            VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, port)).map_err(Error::VsockBind)?;

        let (vsock, _) = listener.accept().map_err(Error::VsockAccept)?;

        Ok(vsock)
    }
}

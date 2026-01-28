// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{
    args_writer::EnclaveArg,
    proxy::{DeviceProxy, Error, Result},
    VsockPortOffset,
};
use std::{
    io::{ErrorKind, Read, Write},
    mem::size_of,
    os::{
        fd::{FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
    time::Duration,
};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

/// Network proxy. Forwards data to/from a UNIX socket and vsock within an enclave to provide
/// network access.
pub struct NetProxy {
    // Unix socket connected to service providing network access.
    unix: UnixStream,
    // Buffer to send/receive data to/from vsock.
    buf: Vec<u8>,
}

impl TryFrom<RawFd> for NetProxy {
    type Error = Error;

    fn try_from(fd: RawFd) -> Result<Self> {
        let buf = Vec::new();

        let unix = unsafe { UnixStream::from(OwnedFd::from_raw_fd(fd)) };
        unix.set_read_timeout(Some(Duration::from_millis(250)))
            .map_err(Error::UnixReadTimeoutSet)?;

        Ok(Self { buf, unix })
    }
}

impl DeviceProxy for NetProxy {
    /// Enclave argument of the proxy.
    fn arg(&self) -> Option<EnclaveArg<'_>> {
        Some(EnclaveArg::NetworkProxy)
    }

    /// Clone a proxy's contents (notably, its connected unix socket).
    fn clone(&self) -> Result<Option<Box<dyn DeviceProxy>>> {
        let unix = self.unix.try_clone().map_err(Error::UnixClone)?;

        Ok(Some(Box::new(Self {
            buf: self.buf.clone(),
            unix,
        })))
    }

    /// Receive data from the proxy's vsock. Forward the data to the connected unix socket.
    fn rcv(&mut self, vsock: &mut VsockStream) -> Result<usize> {
        let size = vsock.read(&mut self.buf).map_err(Error::VsockRead)?;
        if size > 0 {
            self.unix
                .write_all(&self.buf[..size])
                .map_err(Error::UnixWrite)?;
        }

        Ok(size)
    }

    /// Receive data from the connected unix socket. Forward the data to the proxy's vsock.
    fn send(&mut self, vsock: &mut VsockStream) -> Result<usize> {
        match self.unix.read(&mut self.buf) {
            Ok(size) => {
                if size > 0 {
                    let _ = vsock.write_all(&self.buf[..size]);
                }

                Ok(size)
            }
            // No data read from unix socket before timeout.
            Err(ref e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                Ok(0)
            }
            Err(e) => Err(Error::UnixRead(e)),
        }
    }

    /// Establish the proxy's vsock connection.
    fn vsock(&mut self, cid: u32) -> Result<VsockStream> {
        let port = cid + (VsockPortOffset::Net as u32);

        let listener =
            VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, port)).map_err(Error::VsockBind)?;

        let (mut vsock, _) = listener.accept().map_err(Error::VsockAccept)?;

        /*
         * Upon initial connection, read the MTU size from the enclave and allocate the buffer
         * accordingly.
         */
        let size = {
            let mut size_buf = [0u8; size_of::<u32>()];
            let _ = vsock.read(&mut size_buf).map_err(Error::VsockRead)?;

            u32::from_ne_bytes(size_buf)
        };

        self.buf
            .resize(size.try_into().map_err(Error::VsockBufferLenConvert)?, 0);

        Ok(vsock)
    }
}

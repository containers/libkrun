// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{
    proxy::{EnclaveArg, Error, Result},
    DeviceProxy, VsockPortOffset,
};
use signal_hook::consts::SIGTERM;
use std::{
    io::{ErrorKind, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

/// Signal handler proxy. Forwards signals from the host to the enclave. Currently, only SIGTERM is
/// supported.
#[derive(Clone)]
pub struct SignalHandler {
    // Signal hook to determine when a SIGTERM is caught.
    sig: Arc<AtomicBool>,
    // Buffer to forward the SIGTERM to the enclave.
    buf: [u8; 1],
}

impl SignalHandler {
    /// Create a new signal handler proxy with the SIGTERM hook set to false (not caught yet).
    pub fn new() -> Result<Self> {
        let sig = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(SIGTERM, Arc::clone(&sig)).map_err(Error::SignalRegister)?;

        let buf = [0u8; 1];

        Ok(Self { sig, buf })
    }
}

impl DeviceProxy for SignalHandler {
    /// Enclave argument of the proxy.
    fn arg(&self) -> Option<EnclaveArg<'_>> {
        None
    }

    /// Clone a proxy's contents. The cloned signal handler is not used, only the vsock connection.
    fn clone(&self) -> Result<Option<Box<dyn DeviceProxy>>> {
        Ok(Some(Box::new(Clone::clone(self))))
    }

    /// Receive data from the proxy's vsock. This should never read any actual data, but be a
    /// placeholder to indicate that the enclave has closed the vsock connection.
    fn rcv(&mut self, vsock: &mut VsockStream) -> Result<usize> {
        vsock.read(&mut self.buf).map_err(Error::VsockRead)
    }

    /// Check if a SIGTERM was caught. If so, write the signal to the enclave indicating it should
    /// gracefully shut down.
    fn send(&mut self, vsock: &mut VsockStream) -> Result<usize> {
        if !self.sig.load(Ordering::Relaxed) {
            return Ok(0);
        }

        let sig = libc::SIGTERM;
        match vsock.write(&sig.to_ne_bytes()) {
            Ok(size) => Ok(size),
            /*
             * If connection was already closed by enclave, return zero bytes written in order to
             * listen for receiver shutdown signal.
             */
            Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(0),
            Err(e) => Err(Error::VsockWrite(e)),
        }
    }

    /// Establish the proxy's vsock connection.
    fn vsock(&mut self, cid: u32) -> Result<VsockStream> {
        let port = cid + (VsockPortOffset::SignalHandler as u32);

        let listener =
            VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, port)).map_err(Error::VsockBind)?;

        let (vsock, _) = listener.accept().map_err(Error::VsockAccept)?;

        Ok(vsock)
    }
}

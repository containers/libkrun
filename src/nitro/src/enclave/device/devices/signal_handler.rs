// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{
    device::{EnclaveArg, Error, Result},
    DeviceProxy, VsockPortOffset,
};
use signal_hook::consts::SIGTERM;
use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

#[derive(Clone)]
pub struct SignalHandler {
    sig: Arc<AtomicBool>,
    buf: [u8; 1],
}

impl SignalHandler {
    pub fn new() -> Result<Self> {
        let sig = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(SIGTERM, Arc::clone(&sig)).map_err(Error::SignalRegister)?;

        let buf = [0u8; 1];

        Ok(Self { sig, buf })
    }
}

impl DeviceProxy for SignalHandler {
    fn clone(&self) -> Result<Option<Box<dyn DeviceProxy>>> {
        Ok(Some(Box::new(Clone::clone(self))))
    }
    fn enclave_arg(&self) -> Option<EnclaveArg<'_>> {
        None
    }
    fn port_offset(&self) -> VsockPortOffset {
        VsockPortOffset::SignalHandler
    }
    fn rcv(&mut self, vsock: &mut VsockStream) -> Result<usize> {
        vsock.read(&mut self.buf).map_err(Error::VsockRead)
    }

    fn send(&mut self, vsock: &mut VsockStream) -> Result<usize> {
        if !self.sig.load(Ordering::Relaxed) {
            return Ok(0);
        }

        let sig = libc::SIGTERM;
        vsock.write(&sig.to_ne_bytes()).map_err(Error::VsockWrite)?;

        Ok(0)
    }
    fn vsock(&self, port: u32) -> Result<VsockStream> {
        let listener =
            VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, port)).map_err(Error::VsockBind)?;

        let (vsock, _) = listener.accept().map_err(Error::VsockAccept)?;

        Ok(vsock)
    }
}

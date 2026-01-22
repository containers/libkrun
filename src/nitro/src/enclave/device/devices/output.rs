// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{
    args_writer::EnclaveArg,
    device::{DeviceProxy, Error},
    VsockPortOffset,
};
use std::{
    fs::File,
    fs::OpenOptions,
    io::{Read, Write},
    path::PathBuf,
};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY, VMADDR_CID_HYPERVISOR};

type Result<T> = std::result::Result<T, Error>;

pub struct OutputProxy {
    file: File,
    debug: bool,
    buf: [u8; 1500],
}

impl OutputProxy {
    pub fn new(path: &PathBuf, debug: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .read(false)
            .write(true)
            .open(path)
            .map_err(Error::FileOpen)?;

        let buf = [0u8; 1500];

        Ok(Self { file, debug, buf })
    }
}

impl DeviceProxy for OutputProxy {
    fn clone(&self) -> Result<Option<Box<dyn DeviceProxy>>> {
        Ok(None)
    }
    fn enclave_arg(&self) -> Option<EnclaveArg<'_>> {
        match self.debug {
            true => Some(EnclaveArg::Debug),
            false => None,
        }
    }
    fn port_offset(&self) -> VsockPortOffset {
        match self.debug {
            true => VsockPortOffset::Console,
            false => VsockPortOffset::AppOutput,
        }
    }
    fn rcv(&mut self, vsock: &mut VsockStream) -> Result<usize> {
        let size = vsock.read(&mut self.buf).map_err(Error::VsockRead)?;
        if size > 0 {
            self.file
                .write_all(&self.buf[..size])
                .map_err(Error::FileWrite)?;
        }

        Ok(size)
    }
    fn send(&mut self, _vsock: &mut VsockStream) -> Result<usize> {
        Ok(0)
    }
    fn vsock(&self, port: u32) -> Result<VsockStream> {
        let vsock = if self.debug {
            VsockStream::connect(&VsockAddr::new(VMADDR_CID_HYPERVISOR, port))
                .map_err(Error::VsockConnect)?
        } else {
            let listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, port))
                .map_err(Error::VsockBind)?;

            let (vsock, _) = listener.accept().map_err(Error::VsockAccept)?;

            vsock
        };

        Ok(vsock)
    }
}

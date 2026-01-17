// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{
    args_writer::EnclaveArg,
    device::{DeviceProxy, Error, VsockPortOffset},
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
}

impl OutputProxy {
    pub fn new(path: &PathBuf, debug: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .read(false)
            .write(true)
            .open(path)
            .map_err(Error::FileOpen)?;

        Ok(Self { file, debug })
    }
}

impl DeviceProxy for OutputProxy {
    fn enclave_arg(&self) -> Option<EnclaveArg<'_>> {
        match self.debug {
            true => Some(EnclaveArg::Debug),
            false => None,
        }
    }

    fn vsock_port_offset(&self) -> VsockPortOffset {
        match self.debug {
            true => VsockPortOffset::Console,
            false => VsockPortOffset::AppOutput,
        }
    }

    fn _start(&mut self, vsock_port: u32) -> Result<()> {
        let mut vsock_stream = if self.debug {
            VsockStream::connect(&VsockAddr::new(VMADDR_CID_HYPERVISOR, vsock_port))
                .map_err(Error::VsockConnect)?
        } else {
            let vsock_listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, vsock_port))
                .map_err(Error::VsockBind)?;

            let (vsock_stream, _vsock_addr) =
                vsock_listener.accept().map_err(Error::VsockAccept)?;

            vsock_stream
        };

        let mut vsock_buf = [0u8; 1500];
        loop {
            let size = vsock_stream
                .read(&mut vsock_buf)
                .map_err(Error::VsockRead)?;

            if size > 0 {
                self.file
                    .write_all(&vsock_buf[..size])
                    .map_err(Error::FileWrite)?;
            } else {
                break;
            }
        }

        Ok(())
    }
}

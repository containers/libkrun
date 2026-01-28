// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{
    args_writer::EnclaveArg,
    proxy::{DeviceProxy, Error},
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

const OUTPUT_BUFFER_SIZE: usize = 1500;

/// Output proxy. May output application process logs or (in debug mode) kernel+initramfs logs as
// well.
pub struct OutputProxy {
    // The file to write enclave output to.
    file: File,
    // Indicator of debug mode.
    debug: bool,
    // Buffer to receive data from the vsock.
    buf: Vec<u8>,
}

impl OutputProxy {
    /// Open the file in which to forward enclave output to.
    pub fn new(path: &PathBuf, debug: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .read(false)
            .write(true)
            .open(path)
            .map_err(Error::FileOpen)?;

        Ok(Self {
            file,
            debug,
            buf: vec![0u8; OUTPUT_BUFFER_SIZE],
        })
    }
}

impl DeviceProxy for OutputProxy {
    /// Enclave argument of the proxy.
    fn arg(&self) -> Option<EnclaveArg<'_>> {
        // The enclave only needs to be made aware that it is to be run in debug mode.
        match self.debug {
            true => Some(EnclaveArg::Debug),
            false => None,
        }
    }

    /// The output proxy doesn't send any data to the enclave, so there is no need for cloning it
    /// for a sender thread.
    fn clone(&self) -> Result<Option<Box<dyn DeviceProxy>>> {
        Ok(None)
    }

    /// Receive data from the proxy's vsock. Forward the data to the output file.
    fn rcv(&mut self, vsock: &mut VsockStream) -> Result<usize> {
        let size = vsock.read(&mut self.buf).map_err(Error::VsockRead)?;
        if size > 0 {
            self.file
                .write_all(&self.buf[..size])
                .map_err(Error::FileWrite)?;
        }

        Ok(size)
    }

    /// The output proxy does not send data to the enclave.
    fn send(&mut self, _vsock: &mut VsockStream) -> Result<usize> {
        Ok(0)
    }

    /// Establish the proxy's vsock connection.
    fn vsock(&mut self, cid: u32) -> Result<VsockStream> {
        // If debug mode is enabled, connect to the enclave's console for kernel+initramfs logs.
        let port = {
            let offset = match self.debug {
                true => VsockPortOffset::Console,
                false => VsockPortOffset::AppOutput,
            };

            cid + (offset as u32)
        };

        // If debug mode is enabled, the enclave already binds to the console vsock.
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

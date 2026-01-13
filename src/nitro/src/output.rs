// SPDX-License-Identifier: Apache-2.0

use crate::enclaves::VsockPortOffset;
use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Read, Write},
    path::PathBuf,
};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY, VMADDR_CID_HYPERVISOR};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    FileOpen(io::Error),
    FileWrite(io::Error),
    VsockAccept(io::Error),
    VsockBind(io::Error),
    VsockConnect(io::Error),
    VsockRead(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::FileOpen(cause) => format!("unable to open console output file: {:?}", cause),
            Self::FileWrite(cause) => {
                format!("unable to write console buffer to output file: {:?}", cause)
            }
            Self::VsockAccept(cause) => format!(
                "unable to accept connection from enclave output vsock: {:?}",
                cause
            ),
            Self::VsockBind(cause) => {
                format!("unable to bind to enclave output vsock: {:?}", cause)
            }
            Self::VsockConnect(cause) => format!(
                "uanble to connect to enclave console port vsock: {:?}",
                cause
            ),
            Self::VsockRead(cause) => {
                format!("unable to read from enclave output vsock: {:?}", cause)
            }
        };

        write!(f, "{}", msg)
    }
}

pub fn output_proxy(path: &PathBuf, cid: u32, debug: bool) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(false)
        .write(true)
        .open(path)
        .map_err(Error::FileOpen)?;

    let mut vsock_stream = if debug {
        VsockStream::connect(&VsockAddr::new(
            VMADDR_CID_HYPERVISOR,
            cid + (VsockPortOffset::Console as u32),
        ))
        .map_err(Error::VsockConnect)?
    } else {
        let vsock_listener = VsockListener::bind(&VsockAddr::new(
            VMADDR_CID_ANY,
            cid + (VsockPortOffset::AppOutput as u32),
        ))
        .map_err(Error::VsockBind)?;

        let (vsock_stream, _vsock_addr) = vsock_listener.accept().map_err(Error::VsockAccept)?;

        vsock_stream
    };

    let mut vsock_buf = [0u8; 1500];
    loop {
        let size = vsock_stream
            .read(&mut vsock_buf)
            .map_err(Error::VsockRead)?;

        if size > 0 {
            file.write_all(&vsock_buf[..size])
                .map_err(Error::FileWrite)?;
        } else {
            break;
        }
    }

    Ok(())
}

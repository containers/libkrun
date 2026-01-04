// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Read, Write},
    path::PathBuf,
};
use vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

const ENCLAVE_VSOCK_PORT_OUTPUT: u32 = 8081;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    FileOpen(io::Error),
    FileWrite(io::Error),
    VsockAccept(io::Error),
    VsockBind(io::Error),
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
            Self::VsockRead(cause) => {
                format!("unable to read from enclave output vsock: {:?}", cause)
            }
        };

        write!(f, "{}", msg)
    }
}

pub fn output_proxy(path: &PathBuf) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(false)
        .write(true)
        .open(path)
        .map_err(Error::FileOpen)?;

    let vsock_listener =
        VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, ENCLAVE_VSOCK_PORT_OUTPUT))
            .map_err(Error::VsockBind)?;

    let mut vsock_stream = vsock_listener.accept().map_err(Error::VsockAccept)?;

    let mut vsock_buf = [0u8; 1500];
    loop {
        let size = vsock_stream
            .0
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

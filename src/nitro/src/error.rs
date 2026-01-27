// SPDX-License-Identifier: Apache-2.0

use super::enclave::{args_writer, proxy};
use std::{fmt, io};

/// Error in the running of a nitro enclave.
#[derive(Debug)]
pub enum Error {
    // Application running within the enclave returned a non-zero return code.
    AppReturn(i32),
    // Argument writing process.
    ArgsWrite(args_writer::Error),
    // Error in device proxy execution.
    DeviceProxy(proxy::Error),
    // Error in listener for application return code.
    ReturnCodeListener(return_code::Error),
    // Error in rootfs tar archiving.
    RootFsArchive(io::Error),
    // Error in launching the enclave.
    Start(start::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::AppReturn(ret) => format!("app returned non-zero return code: {ret}"),
            Self::ArgsWrite(e) => format!("enclave VM argument writer error: {e}"),
            Self::DeviceProxy(e) => format!("device proxy error: {e}"),
            Self::ReturnCodeListener(e) => {
                format!("error with enclave VM return code listener: {e}")
            }
            Self::RootFsArchive(e) => {
                format!("unable to archive rootfs: {e}")
            }
            Self::Start(e) => format!("error launching enclave VM: {e}"),
        };

        write!(f, "{}", msg)
    }
}

pub mod start {
    use super::*;
    use nitro_enclaves::launch::LaunchError;

    /// Error in launching the enclave.
    #[derive(Debug)]
    pub enum Error {
        // Opening the /dev/nitro_enclaves device.
        DeviceOpen(io::Error),
        // Reading the cached EIF.
        EifRead(io::Error),
        // Calculating the poll timeout.
        PollTimeoutCalculate(LaunchError),
        // Adding a vCPU to an enclave VM.
        VcpuAdd(LaunchError),
        // Creating the enclave VM.
        VmCreate(LaunchError),
        // Setting the enclave VM's memory.
        VmMemorySet(LaunchError),
        // Starting the enclave VM.
        VmStart(LaunchError),
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let msg = match self {
                Self::DeviceOpen(e) => format!("unable to open nitro enclaves device: {e}"),
                Self::EifRead(e) => format!("unable to read cached EIF file: {e}"),
                Self::PollTimeoutCalculate(e) => {
                    format!("unable to calculate vsock poll timeout for enclave VM: {e}")
                }
                Self::VcpuAdd(e) => format!("unable to add vCPU to enclave VM: {e}"),
                Self::VmCreate(e) => format!("unable to create enclave VM: {e}"),
                Self::VmMemorySet(e) => {
                    format!("unable to set enclave VM memory regions: {e}")
                }
                Self::VmStart(e) => format!("unable to start enclave VM: {e}"),
            };

            write!(f, "{}", msg)
        }
    }
}

pub mod return_code {
    use super::*;

    /// Error in listener for application return code.
    #[derive(Debug)]
    #[allow(clippy::enum_variant_names)]
    pub enum Error {
        // Accepting the vsock connection.
        VsockAccept(io::Error),
        // Binding to the vsock.
        VsockBind(io::Error),
        // Reading from the vsock.
        VsockRead(io::Error),
        // Writing to the vsock.
        VsockWrite(io::Error),
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let msg = match self {
                Self::VsockAccept(e) => format!("unable to accept vsock connection: {e}"),
                Self::VsockBind(e) => format!("unable to bind to vsock: {e}"),
                Self::VsockRead(e) => format!("unable to read from vsock: {e}"),
                Self::VsockWrite(e) => format!("unable to write to vsock: {e}"),
            };

            write!(f, "{}", msg)
        }
    }
}

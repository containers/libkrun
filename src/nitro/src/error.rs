// SPDX-License-Identifier: Apache-2.0

use super::enclave::{args_writer, device};
use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    AppReturn(i32),
    ArgsWrite(args_writer::Error),
    Device(device::Error),
    ReturnCodeListener(return_code::Error),
    RootFsArchive(io::Error),
    Start(start::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::AppReturn(ret) => format!("app returned non-zero return code: {ret}"),
            Self::ArgsWrite(e) => format!("enclave VM argument writer error: {e}"),
            Self::Device(e) => format!("device proxy error: {e}"),
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

    #[derive(Debug)]
    pub enum Error {
        DeviceOpen(io::Error),
        EifRead(io::Error),
        PollTimeoutCalculate(LaunchError),
        VcpuAdd(LaunchError),
        VmCreate(LaunchError),
        VmMemorySet(LaunchError),
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

    #[derive(Debug)]
    #[allow(clippy::enum_variant_names)]
    pub enum Error {
        VsockAccept(io::Error),
        VsockBind(io::Error),
        VsockRead(io::Error),
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let msg = match self {
                Self::VsockAccept(e) => format!("unable to accept vsock connection: {e}"),
                Self::VsockBind(e) => format!("unable to bind to vsock: {e}"),
                Self::VsockRead(e) => format!("unable to read from vsock: {e}"),
            };

            write!(f, "{}", msg)
        }
    }
}

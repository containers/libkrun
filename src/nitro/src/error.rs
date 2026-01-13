// SPDX-License-Identifier: Apache-2.0

use super::device;
use nitro_enclaves::launch::LaunchError;
use std::{ffi, fmt, io};

#[derive(Debug)]
pub enum NitroError {
    DeviceOpen(io::Error),
    VmCreate(LaunchError),
    VmMemorySet(LaunchError),
    VcpuAdd(LaunchError),
    HeartbeatAccept(io::Error),
    HeartbeatBind(io::Error),
    HeartbeatRead(io::Error),
    HeartbeatWrite(io::Error),
    VmStart(LaunchError),
    PollTimeoutCalculate(LaunchError),
    PollNoSelectedEvents,
    PollMoreThanOneSelectedEvent,
    EnclaveHeartbeatNotDetected,
    RootFsArchive(io::Error),
    HeartbeatCidMismatch,
    VsockCreate,
    VsockSetTimeout,
    VsockConnect,
    IpcWrite(io::Error),
    VsockBytesLenWrite(io::Error),
    VsockBytesWrite(io::Error),
    VsockBytesTooLarge,
    CStringConversion(ffi::NulError),
    EifTarExtract(io::Error),
    DeviceError(device::Error),
}

impl fmt::Display for NitroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            NitroError::DeviceOpen(e) => format!("unable to open nitro enclaves device: {e}"),
            NitroError::VmCreate(e) => format!("unable to create enclave VM: {e}"),
            NitroError::VmMemorySet(e) => format!("unable to set enclave memory regions: {e}"),
            NitroError::VcpuAdd(e) => format!("unable to add vCPU to enclave: {e}"),
            NitroError::HeartbeatAccept(e) => {
                format!("unable to accept enclave heartbeat vsock: {e}")
            }
            NitroError::HeartbeatBind(e) => {
                format!("unable to bind to enclave heartbeat vsock: {e}")
            }
            NitroError::HeartbeatRead(e) => format!("unable to read enclave heartbeat vsock: {e}"),
            NitroError::HeartbeatWrite(e) => {
                format!("unable to write to enclave heartbeat vsock: {e}")
            }
            NitroError::VmStart(e) => format!("unable to start enclave: {e}"),
            NitroError::PollTimeoutCalculate(e) => {
                format!("unable to calculate vsock poll timeout: {e}")
            }
            NitroError::PollNoSelectedEvents => {
                "no selected poll fds for heartbeat vsock found".to_string()
            }
            NitroError::PollMoreThanOneSelectedEvent => {
                "more than one selected pollfd for heartbeat vsock found".to_string()
            }
            NitroError::EnclaveHeartbeatNotDetected => {
                "enclave heartbeat message not detected".to_string()
            }
            NitroError::HeartbeatCidMismatch => "enclave heartbeat vsock CID mismatch".to_string(),
            NitroError::VsockCreate => "unable to create enclave vsock".to_string(),
            NitroError::VsockSetTimeout => {
                "unable to set poll timeout for enclave vsock".to_string()
            }
            NitroError::VsockConnect => "unable to connect to enclave vsock".to_string(),
            NitroError::RootFsArchive(e) => {
                format!("unable to archive rootfs: {e}")
            }
            NitroError::IpcWrite(e) => {
                format!("unable to write enclave vsock data to UNIX IPC socket: {e}")
            }
            NitroError::VsockBytesLenWrite(e) => {
                format!("unable to write rootfs archive length to enclave: {e}")
            }
            NitroError::VsockBytesWrite(e) => {
                format!("unable to write rootfs archive to enclave: {e}")
            }
            NitroError::VsockBytesTooLarge => {
                "vsock write byte buffer size is larger than 64 bytes".to_string()
            }
            NitroError::CStringConversion(e) => format!("unable to convert String to CString: {e}"),
            NitroError::EifTarExtract(e) => format!("unable to extract EIF from tar archive: {e}"),
            NitroError::DeviceError(e) => format!("device proxy error: {:?}", e),
        };

        write!(f, "{}", msg)
    }
}

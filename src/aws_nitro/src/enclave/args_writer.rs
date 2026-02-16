// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{proxy::DeviceProxyList, VsockPortOffset};
use libc::c_int;
use nitro_enclaves::launch::PollTimeout;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout as NixPollTimeout};
use std::{
    ffi::{self, CString},
    fmt,
    io::{self, Read, Write},
    num::TryFromIntError,
    os::fd::AsFd,
    str::FromStr,
};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

// A known byte that libkrun-awsnitro and the enclave initramfs will exchange to confirm that startup
// was successful and the initramfs is ready to begin reading enclave arguments.
const ENCLAVE_VSOCK_LAUNCH_ARGS_READY: u8 = 0xb7;

type Result<T> = std::result::Result<T, Error>;

/// The service responsible for writing the configuration (rootfs, execution environment, and
// optional device proxies) to the enclave.
#[derive(Debug, Default)]
pub struct EnclaveArgsWriter<'a> {
    // List of enclave arguments.
    pub args: Vec<EnclaveArg<'a>>,
}

impl<'a> EnclaveArgsWriter<'a> {
    /// Create a new arguments writer. An enclave's rootfs and execution path are required
    /// arguments. Some device proxies are required, but others are optional.
    pub fn new(
        rootfs_archive: &'a [u8],
        exec_path: &str,
        argv_str: &str,
        envp_str: &str,
        proxies: &'a DeviceProxyList,
    ) -> Self {
        let mut args: Vec<EnclaveArg<'a>> = Vec::new();

        // Split the argv string into a vector.
        let argv: Vec<String> = argv_str
            .replace("\"", "")
            .split(' ')
            .map(|s| s.to_string())
            .collect();

        // Split the envp string into a vector.
        let envp: Vec<String> = envp_str
            .replace("\"", "")
            .split(' ')
            .map(|s| s.to_string())
            .collect();

        // Create the initial argument list from the required arguments.
        args.append(&mut vec![
            EnclaveArg::RootFilesystem(rootfs_archive),
            EnclaveArg::ExecPath(exec_path.to_string()),
            EnclaveArg::ExecArgv(argv),
            EnclaveArg::ExecEnvp(envp),
        ]);

        // Add an enclave argument for each device proxy that includes one. Any optional device
        // proxy has an enclave argument.
        for proxy in &proxies.0 {
            if let Some(arg) = proxy.arg() {
                args.push(arg);
            }
        }

        Self { args }
    }

    /// Write the arguments to the enclave.
    pub fn write_args(&self, cid: u32, timeout: PollTimeout) -> Result<()> {
        // Establish a vsock connection to the enclave's initramfs.
        let listener = VsockListener::bind(&VsockAddr::new(
            VMADDR_CID_ANY,
            cid + (VsockPortOffset::ArgsReader as u32),
        ))
        .map_err(Error::VsockBind)?;

        self.poll(&listener, timeout)?;

        let mut stream = listener.accept().map_err(Error::VsockAccept)?;

        if stream.1.cid() != cid {
            return Err(Error::VsockCidMismatch);
        }

        // Exchange the ready signal to ensure the initramfs is ready to receive arguments.
        let mut buf = [0u8];
        let bytes = stream.0.read(&mut buf).map_err(Error::VsockRead)?;

        if bytes != 1 || buf[0] != ENCLAVE_VSOCK_LAUNCH_ARGS_READY {
            return Err(Error::ReadySignalNotDetected);
        }

        stream.0.write_all(&buf).map_err(Error::VsockWrite)?;

        // Write each argument.
        for arg in &self.args {
            arg.write(&mut stream.0)?;
        }

        // Notify the enclave that the args are finished being written.
        let finished = EnclaveArg::Finished;
        finished.write(&mut stream.0)?;

        Ok(())
    }

    /// The enclave's initramfs may take some time to connect over vsock. Poll for the connection.
    fn poll(&self, listener: &VsockListener, timeout: PollTimeout) -> Result<()> {
        let mut poll_fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
        let result = poll(
            &mut poll_fds,
            NixPollTimeout::from(c_int::from(timeout) as u16),
        );

        match result {
            Ok(0) => Err(Error::PollNoEvents),
            Ok(x) if x > 1 => Err(Error::PollMoreThanOneSelectedEvent),
            _ => Ok(()),
        }
    }
}

/// An enclave argument.
#[derive(Debug)]
pub enum EnclaveArg<'a> {
    // Enclave rootfs.
    RootFilesystem(&'a [u8]),
    // Enclave execution environment (path, argv, envp).
    ExecPath(String),
    ExecArgv(Vec<String>),
    ExecEnvp(Vec<String>),
    // Network proxy.
    NetworkProxy,
    // Application output.
    AppOutput,

    // Placeholder argument where libkrun notifies the initramfs that all arguments have been
    // written and it can now close the vsock connection.
    Finished,
}

/// Each argument has a unique code/ID for the initramfs to understand how to read its parameters.
/// This code is represented as a one-byte value.
impl From<&EnclaveArg<'_>> for u8 {
    fn from(arg: &EnclaveArg) -> u8 {
        match arg {
            EnclaveArg::RootFilesystem(_) => 0,
            EnclaveArg::ExecPath(_) => 1,
            EnclaveArg::ExecArgv(_) => 2,
            EnclaveArg::ExecEnvp(_) => 3,
            EnclaveArg::NetworkProxy => 4,
            EnclaveArg::AppOutput => 5,

            EnclaveArg::Finished => 255,
        }
    }
}

impl EnclaveArg<'_> {
    /// Write an argument to the enclave.
    fn write(&self, vsock: &mut VsockStream) -> Result<()> {
        let id: [u8; 1] = [self.into()];

        // Write the argument's ID for the enclave to understand how to read the argument's
        // parameters.
        vsock.write_all(&id).map_err(Error::VsockWrite)?;

        match self {
            // rootfs argument writes the rootfs tar archive.
            Self::RootFilesystem(buf) => {
                let len: u64 = buf.len().try_into().map_err(Error::VsockBufferLenConvert)?;

                vsock
                    .write_all(&len.to_ne_bytes())
                    .map_err(Error::VsockWrite)?;

                vsock.write_all(buf).map_err(Error::VsockWrite)?;
            }
            // Execution argv and envp arguments write their respective contents as string arrays.
            Self::ExecArgv(vec) | Self::ExecEnvp(vec) => {
                // Write the amount of strings the enclave will read.
                let len: u64 = vec.len().try_into().map_err(Error::VsockBufferLenConvert)?;

                vsock
                    .write_all(&len.to_ne_bytes())
                    .map_err(Error::VsockWrite)?;

                // For each string, write the length (i.e. the number of bytes the enclave should
                // read) and the string itself.
                for string in vec {
                    let bytes = Vec::from(
                        CString::from_str(string)
                            .map_err(Error::CStringConvert)?
                            .as_bytes_with_nul(),
                    );

                    let len: u64 = bytes
                        .len()
                        .try_into()
                        .map_err(Error::VsockBufferLenConvert)?;

                    vsock
                        .write_all(&len.to_ne_bytes())
                        .map_err(Error::VsockWrite)?;

                    vsock.write_all(&bytes).map_err(Error::VsockWrite)?;
                }
            }
            // Execution path argument writes the path as a string.
            Self::ExecPath(buf) => {
                let bytes = Vec::from(
                    CString::from_str(buf)
                        .map_err(Error::CStringConvert)?
                        .as_bytes_with_nul(),
                );
                let len: u64 = bytes
                    .len()
                    .try_into()
                    .map_err(Error::VsockBufferLenConvert)?;

                vsock
                    .write_all(&len.to_ne_bytes())
                    .map_err(Error::VsockWrite)?;

                vsock.write_all(&bytes).map_err(Error::VsockWrite)?;
            }

            // Other arguments write solely their ID. The enclave will initialize them.
            _ => (),
        }

        Ok(())
    }
}

/// Error in the process of writing the enclave's arguments.
#[derive(Debug)]
pub enum Error {
    // Convert a string to a CString.
    CStringConvert(ffi::NulError),
    // No events detected on vsock.
    PollNoEvents,
    // More than one event found on vsock.
    PollMoreThanOneSelectedEvent,
    // Ready signal not detected.
    ReadySignalNotDetected,
    // Accepting the vsock connection.
    VsockAccept(io::Error),
    // Binding to the vsock.
    VsockBind(io::Error),
    // Converting a byte buffer's length to a u64.
    VsockBufferLenConvert(TryFromIntError),
    // CID mismatch with communicating enclave.
    VsockCidMismatch,
    // Reading from the vsock.
    VsockRead(io::Error),
    // Writing to the vsock.
    VsockWrite(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::CStringConvert(e) => format!("unable to convert string to CString: {e}"),
            Self::PollNoEvents => "no events on vsock detected".to_string(),
            Self::PollMoreThanOneSelectedEvent => {
                "more than one event on vsock detected".to_string()
            }
            Self::ReadySignalNotDetected => "ready signal not detected".to_string(),
            Self::VsockAccept(e) => format!("unable to accept vsock connection: {e}"),
            Self::VsockBind(e) => format!("unable to bind to vsock: {e}"),
            Self::VsockBufferLenConvert(e) => {
                format!("unable to convert vsock buffer size to u64: {e}")
            }
            Self::VsockCidMismatch => "CID mismatch on vsock".to_string(),
            Self::VsockRead(e) => format!("unable to read from vsock: {e}"),
            Self::VsockWrite(e) => format!("unable to write to vsock: {e}"),
        };

        write!(f, "{}", msg)
    }
}

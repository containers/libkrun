// SPDX-License-Identifier: Apache-2.0

mod proxies;

pub use proxies::*;

use crate::enclave::args_writer::EnclaveArg;
use std::{
    fmt, io,
    num::TryFromIntError,
    sync::mpsc::{self, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::Duration,
};
use vsock::*;

type Result<T> = std::result::Result<T, Error>;

/// Device proxy trait to describe shared behavior between all proxies.
pub trait DeviceProxy: Send {
    /// Enclave argument of the proxy.
    fn arg(&self) -> Option<EnclaveArg<'_>>;
    /// Clone a proxy's contents.
    fn clone(&self) -> Result<Option<Box<dyn DeviceProxy>>>;
    /// Receive data from the proxy's vsock. Perhaps perform some other functions.
    fn rcv(&mut self, vsock: &mut VsockStream) -> Result<usize>;
    /// Write data to the enclave's vsock. Perhaps perform some other functions.
    fn send(&mut self, vsock: &mut VsockStream) -> Result<usize>;
    /// Establish the proxy's respective vsock connection.
    fn vsock(&mut self, cid: u32) -> Result<VsockStream>;
}

/// List of all configured device proxies.
pub struct DeviceProxyList(pub Vec<Box<dyn Send + DeviceProxy>>);

impl DeviceProxyList {
    /// Run each proxy's send and receive processes within their own dedicated threads.
    pub fn run(self, cid: u32) -> Result<()> {
        // This function will not return until all device proxies' dedicated threads have returned.
        // Under normal conditions, this will only happen when the enclave completes execution and
        // gracefully closes all proxy vsock connections. Store each thread's JoinHandle in a list
        // to keep track of completed proxy threads.
        let mut handles: Vec<JoinHandle<Result<()>>> = Vec::new();

        for mut proxy in self.0 {
            // Get a proxy's vsock connection for the its receiver thread.
            let mut vsock_rcv = proxy.vsock(cid)?;

            let handle: JoinHandle<Result<()>> = thread::spawn(move || {
                // Clone the proxy and vsock connection data for the proxy's sender thread.
                let clone = proxy.clone()?;
                let mut vsock_send = vsock_rcv.try_clone().map_err(Error::VsockClone)?;

                // Establish a message passing channel for the receiver thread to notify the send
                // thread that the enclave has closed the connection.
                let (tx, rx) = mpsc::channel::<()>();

                // Receiver thread. Receive data from the vsock and perform some proxy-dependent
                // action with the data.
                let rcv: JoinHandle<Result<()>> = thread::spawn(move || loop {
                    // Proxy rcv method returns the number of bytes read from the vsock.
                    match proxy.rcv(&mut vsock_rcv) {
                        // Zero bytes read indicates the enclave has closed the vsock connection.
                        // Notify the sender thread that the vsock was closed.
                        Ok(0) => {
                            let _ = tx.send(());
                            return Ok(());
                        }
                        // Bytes were read, continue the receive process.
                        Ok(_) => continue,
                        // An error occured, exit the receiver thread and notify the sender thread to
                        // also exit.
                        Err(e) => {
                            let _ = tx.send(());
                            return Err(e);
                        }
                    }
                });

                // Sender thread. Perform some proxy-dependent action and (if applicable) write data
                // to the vsock.
                let send: JoinHandle<Result<()>> = thread::spawn(move || {
                    // Some proxies (like output/debug) do not send data to the enclave. If there is
                    // nothing to be done, exit the thread.
                    if let Some(mut sender) = clone {
                        loop {
                            // Proxy send method returns the number of bytes written to the vsock.
                            let size = sender.send(&mut vsock_send)?;

                            // No data was written to the vsock. This may indicate that the timeout
                            // has occurred without data being retrieved from the device's other
                            // party. This may indicate that the proxy is complete. Check for this
                            // by reading if a message was sent by the receiver thread.
                            if size == 0 {
                                match rx.recv_timeout(Duration::from_micros(500)) {
                                    // Message was sent indicating the enclave has closed the
                                    // connection, exit from this thread.
                                    Ok(_) => break,
                                    Err(e) => {
                                        // The receiver thread has not sent a shutdown signal.
                                        // Continue execution.
                                        if e == RecvTimeoutError::Timeout {
                                            continue;
                                        } else {
                                            // Error in fetching message from receiver thread.
                                            return Err(Error::ShutdownSignalReceive(e))?;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Ok(())
                });

                if let Ok(Err(e)) = rcv.join() {
                    log::error!("error in device proxy receiver thread: {e}");
                }

                if let Ok(Err(e)) = send.join() {
                    log::error!("error in device proxy sender thread: {e}");
                }

                Ok(())
            });

            // Add the proxy's control thread JoinHandle into the list.
            handles.push(handle);
        }

        // Traverse over each device proxy thread and ensure it closes and exits correctly. Do not
        // return until all do.
        for handle in handles.into_iter() {
            let res = handle.join();
            if let Ok(Err(err)) = res {
                log::error!("error running enclave device proxy: {:?}", err);
            }
        }

        Ok(())
    }
}

/// Error while running a device proxy.
#[derive(Debug)]
pub enum Error {
    // Opening a file (for proxies also communicating with files/sockets).
    FileOpen(io::Error),
    // Writing to a file.
    FileWrite(io::Error),
    // Receiving a shutdown signal from a proxy's receiver thread.
    ShutdownSignalReceive(mpsc::RecvTimeoutError),
    // Registering a signal for the signal handler.
    SignalRegister(io::Error),
    // Cloning a unix socket.
    UnixClone(io::Error),
    // Reading from a unix socket.
    UnixRead(io::Error),
    // Setting the read timeout for a unix socket.
    UnixReadTimeoutSet(io::Error),
    // Writing to a unix socket.
    UnixWrite(io::Error),
    // Accepting the vsock connection.
    VsockAccept(io::Error),
    // Binding to the vsock.
    VsockBind(io::Error),
    // Converting a byte buffer's length to a u64.
    VsockBufferLenConvert(TryFromIntError),
    // Cloning the vsock.
    VsockClone(io::Error),
    // Connecting to the vsock.
    VsockConnect(io::Error),
    // Reading from the vsock.
    VsockRead(io::Error),
    // Writing to the vsock.
    VsockWrite(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::FileOpen(e) => format!("unable to open file: {e}"),
            Self::FileWrite(e) => format!("unable to write buffer to output file: {e}"),
            Self::ShutdownSignalReceive(e) => {
                format!("error while receiving read proxy shutdown signal: {e}")
            }
            Self::SignalRegister(e) => {
                format!("unable to register signal in signal handler proxy: {e}")
            }
            Self::UnixClone(e) => format!("unable to clone unix stream: {e}"),
            Self::UnixRead(e) => format!("unable to read from unix stream: {e}"),
            Self::UnixReadTimeoutSet(e) => {
                format!("unable to set read timeout for unix stream: {e}")
            }
            Self::UnixWrite(e) => format!("unable to write to unix stream: {e}"),
            Self::VsockAccept(e) => format!("unable to accept connection from vsock: {e}"),
            Self::VsockBind(e) => format!("unable to bind to vsock: {e}"),
            Self::VsockBufferLenConvert(e) => {
                format!("unable to convert vsock buffer size to u32: {e}")
            }
            Self::VsockConnect(e) => format!("unable to connect to vsock: {e}"),
            Self::VsockClone(e) => format!("unable to clone vsock: {e}"),
            Self::VsockRead(e) => format!("unable to read from vsock: {e}"),
            Self::VsockWrite(e) => format!("unable to write to vsock: {e}"),
        };

        write!(f, "{}", msg)
    }
}

// SPDX-License-Identifier: Apache-2.0

use crate::enclave::{
    device::{EnclaveArg, Error, Result},
    DeviceProxy, VsockPortOffset,
};
use signal_hook::consts::SIGTERM;
use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

#[derive(Default)]
pub struct SignalHandler;

impl DeviceProxy for SignalHandler {
    fn enclave_arg(&self) -> Option<EnclaveArg<'_>> {
        None
    }

    fn vsock_port_offset(&self) -> VsockPortOffset {
        VsockPortOffset::SignalHandler
    }

    fn _start(&mut self, vsock_port: u32) -> Result<()> {
        let term = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(SIGTERM, Arc::clone(&term)).map_err(Error::SignalRegister)?;

        let vsock_listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, vsock_port))
            .map_err(Error::VsockBind)?;

        let (mut vsock_stream, _vsock_addr) =
            vsock_listener.accept().map_err(Error::VsockAccept)?;

        let (tx, rx) = mpsc::channel::<()>();
        let mut vsock_stream_clone = vsock_stream.try_clone().map_err(Error::VsockClone)?;

        let signal_handler: JoinHandle<Result<()>> = thread::spawn(move || {
            while !term.load(Ordering::Relaxed) {
                match rx.recv_timeout(Duration::from_micros(500)) {
                    Ok(_) => return Ok(()),
                    Err(e) => {
                        if e == RecvTimeoutError::Timeout {
                            continue;
                        }
                    }
                }
            }

            let sig = libc::SIGTERM;
            vsock_stream
                .write(&sig.to_ne_bytes())
                .map_err(Error::VsockWrite)?;

            Ok(())
        });

        let shutdown_listener: JoinHandle<Result<()>> = thread::spawn(move || {
            let mut vsock_buf = [0u8; 1];
            let _ = vsock_stream_clone
                .read(&mut vsock_buf)
                .map_err(Error::VsockRead)?;
            let _ = tx.send(());

            Ok(())
        });

        if let Ok(Err(e)) = signal_handler.join() {
            log::error!("error in signal handler proxy: {e}");
        }

        if let Ok(Err(e)) = shutdown_listener.join() {
            log::error!("error in signal handler device proxy shutdown listener: {e}");
        }

        Ok(())
    }
}

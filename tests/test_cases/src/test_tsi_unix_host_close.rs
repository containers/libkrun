//! On Linux, `make test TEST=tsi-unix-host-close` checks that TSI drains buffered
//! AF_UNIX stream data before handling a host close. The test stops the entire VM
//! after a guest readiness handshake, writes and closes the host stream, then
//! resumes the VM and verifies all 16 KiB of payload and EOF.

use macros::{guest, host};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct TestTsiUnixHostClose;

const PAYLOAD_SIZE: usize = 16 * 1024;

fn stream_set_timeouts(stream: &UnixStream) {
    let timeout = Some(Duration::from_secs(5));
    stream.set_read_timeout(timeout).unwrap();
    stream.set_write_timeout(timeout).unwrap();
}

#[host]
mod host {
    use super::*;

    use anyhow::{bail, ensure};
    use nix::sys::prctl::set_pdeathsig;
    use nix::sys::signal::{kill, Signal};
    use nix::sys::socket::{setsockopt, sockopt::SndBuf};
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::{fork, getpid, getppid, ForkResult, Pid};
    use std::ffi::CString;
    use std::io::ErrorKind;
    use std::os::unix::net::UnixListener;
    use std::thread;

    use crate::common::setup_fs_and_enter_with_env;
    use crate::{krun_call, krun_call_u32, Test, TestSetup};
    use krun_sys::*;

    struct VmProcess(Option<Pid>);

    impl VmProcess {
        fn accept(&mut self, listener: &UnixListener) -> anyhow::Result<UnixStream> {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => return Ok(stream),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
                let status = waitpid(self.0.unwrap(), Some(WaitPidFlag::WNOHANG))?;
                if status != WaitStatus::StillAlive {
                    self.0 = None;
                    bail!("VM exited before connecting: {status:?}");
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for VmProcess {
        fn drop(&mut self) {
            if let Some(pid) = self.0 {
                let _ = kill(pid, Signal::SIGKILL);
                let _ = waitpid(pid, None);
            }
        }
    }

    fn server(listener: UnixListener, pid: Pid) -> anyhow::Result<()> {
        let mut vm = VmProcess(Some(pid));
        listener.set_nonblocking(true)?;
        let mut stream = vm.accept(&listener)?;
        stream_set_timeouts(&stream);
        let mut ready = [0];
        stream.read_exact(&mut ready)?;
        ensure!(ready == [1], "guest readiness byte missing");
        setsockopt(&stream, SndBuf, &(2 * PAYLOAD_SIZE))?;

        // Stop the muxer as well as the vCPUs so unread data and HUP are both
        // pending when the VM resumes, independently of host scheduling.
        kill(pid, Signal::SIGSTOP)?;
        ensure!(
            waitpid(pid, Some(WaitPidFlag::WUNTRACED))?
                == WaitStatus::Stopped(pid, Signal::SIGSTOP),
            "VM did not stop"
        );
        let payload: Vec<u8> = (0..PAYLOAD_SIZE).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload)?;
        drop(stream);
        kill(pid, Signal::SIGCONT)?;

        let status = waitpid(pid, None)?;
        vm.0 = None;
        ensure!(
            status == WaitStatus::Exited(pid, 0),
            "VM exited: {status:?}"
        );
        Ok(())
    }

    impl Test for TestTsiUnixHostClose {
        fn timeout_secs(&self) -> u64 {
            30
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let sock_path = test_setup.tmp_dir.canonicalize()?.join("test.sock");
            let listener = UnixListener::bind(&sock_path)?;
            let parent = getpid();
            // Fork before libkrun starts threads; the supervisor must remain
            // runnable while the entire VM process is stopped.
            match unsafe { fork()? } {
                ForkResult::Parent { child } => return server(listener, child),
                ForkResult::Child => {
                    set_pdeathsig(Signal::SIGKILL)?;
                    ensure!(getppid() == parent, "test supervisor exited");
                    drop(listener);
                }
            }

            let socket_env = CString::new(format!("TSI_SOCKET={}", sock_path.display()))?;
            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 256))?;
                krun_call!(krun_disable_implicit_vsock(ctx))?;
                krun_call!(krun_add_vsock(ctx, KRUN_TSI_HIJACK_UNIX))?;
                setup_fs_and_enter_with_env(ctx, test_setup, &[socket_env.as_c_str()])
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;

    use std::env;

    use crate::Test;

    impl Test for TestTsiUnixHostClose {
        fn in_guest(self: Box<Self>) {
            let mut stream = UnixStream::connect(env::var("TSI_SOCKET").unwrap()).unwrap();
            stream_set_timeouts(&stream);
            stream.write_all(&[1]).unwrap();

            let mut payload = vec![0; PAYLOAD_SIZE];
            stream.read_exact(&mut payload).unwrap();
            assert!(payload
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (i % 251) as u8));
            assert_eq!(stream.read(&mut [0]).unwrap(), 0);
            println!("OK");
        }
    }
}

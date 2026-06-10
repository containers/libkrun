#![cfg(any(feature = "host", target_os = "linux"))]

use macros::{guest, host};
use std::io::{ErrorKind, Read};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct TestVsockGuestConnect;

fn stream_expect_msg(stream: &mut UnixStream, expected: &[u8]) {
    let mut buf = vec![0; expected.len()];
    stream.read_exact(&mut buf[..]).unwrap();
    assert_eq!(&buf[..], expected);
}

fn stream_expect_wouldblock(stream: &mut UnixStream) {
    stream.set_nonblocking(true).unwrap();
    let err = stream.read(&mut [0u8; 1]).unwrap_err();
    stream.set_nonblocking(false).unwrap();
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
}

fn stream_set_timeouts(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
}

const VSOCK_PORT: u32 = 1234;

#[host]
mod host {
    use super::*;

    use crate::common::VmConfig;
    use crate::{Test, TestSetup};
    use krun::{TsiFlags, VsockDevice};
    use std::collections::HashMap;
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::{mem, thread};

    fn server(listener: UnixListener) {
        let (mut stream, _addr) = listener.accept().unwrap();
        stream_set_timeouts(&mut stream);
        stream.write_all(b"ping!").unwrap();
        stream_expect_msg(&mut stream, b"pong!");
        stream_expect_wouldblock(&mut stream);
        stream.write_all(b"bye!").unwrap();
        // Leak the socket fd, to make sure it is not closed early when we exit the thread
        mem::forget(stream);
    }

    impl Test for TestVsockGuestConnect {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let sock_path = test_setup.tmp_dir.join("test.sock");

            let listener = UnixListener::bind(&sock_path).unwrap();
            thread::spawn(move || server(listener));

            let mut unix_ipc_port_map = HashMap::new();
            unix_ipc_port_map.insert(VSOCK_PORT, (sock_path, false));

            let vsock = VsockDevice::new(3, None, Some(unix_ipc_port_map), TsiFlags::empty())?;

            let (mut vm_config, payload) = VmConfig::new(1, 1024, &test_setup)?;
            vm_config.devices.add(vsock);
            vm_config.build_and_run(payload)
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    use nix::libc::VMADDR_CID_HOST;
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, VsockAddr};
    use std::io::Write;
    use std::os::fd::AsRawFd;

    impl Test for TestVsockGuestConnect {
        fn in_guest(self: Box<Self>) {
            let sock = socket(
                AddressFamily::Vsock,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .unwrap();
            let addr = VsockAddr::new(VMADDR_CID_HOST, VSOCK_PORT);
            connect(sock.as_raw_fd(), &addr).unwrap();
            let mut stream = UnixStream::from(sock);
            stream_set_timeouts(&mut stream);

            stream_expect_msg(&mut stream, b"ping!");
            stream_expect_wouldblock(&mut stream);
            stream.write_all(b"pong!").unwrap();
            stream_expect_msg(&mut stream, b"bye!");

            println!("OK");
        }
    }
}

//! Unified virtio-net integration tests
//!
//! All tests follow the same pattern:
//! 1. Host: Start backend + TCP server
//! 2. Guest: Configure eth0 with static IP
//! 3. Guest: Connect to host TCP server

use crate::tcp_tester::TcpTester;
use macros::{guest, host};

#[host]
use crate::{ShouldRun, TestSetup};

#[cfg(feature = "host")]
pub(crate) mod passt;
#[cfg(feature = "host")]
pub(crate) mod tap;
#[cfg(feature = "host")]
pub(crate) mod gvproxy;

/// Virtio-net test with configurable backend
pub struct TestNet {
    guest_ip: [u8; 4],
    host_ip: [u8; 4],
    netmask: [u8; 4],
    port: u16,
    tcp_tester: TcpTester,
    #[cfg(feature = "host")]
    should_run: fn() -> ShouldRun,
    #[cfg(feature = "host")]
    setup_backend: fn(u32, &TestSetup) -> anyhow::Result<()>,
    #[cfg(feature = "host")]
    cleanup: Option<fn()>,
}

impl TestNet {
    pub fn new_passt() -> Self {
        Self {
            guest_ip: [169, 254, 2, 1],
            host_ip: [169, 254, 2, 2],
            netmask: [255, 255, 0, 0],
            port: 9000,
            tcp_tester: TcpTester::new(9000),
            #[cfg(feature = "host")]
            should_run: passt::should_run,
            #[cfg(feature = "host")]
            setup_backend: passt::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_tap() -> Self {
        Self {
            guest_ip: [10, 0, 0, 2],
            host_ip: [10, 0, 0, 1],
            netmask: [255, 255, 255, 0],
            port: 9001,
            tcp_tester: TcpTester::new(9001),
            #[cfg(feature = "host")]
            should_run: tap::should_run,
            #[cfg(feature = "host")]
            setup_backend: tap::setup_backend,
            #[cfg(feature = "host")]
            cleanup: Some(tap::cleanup),
        }
    }

    pub fn new_gvproxy() -> Self {
        Self {
            guest_ip: [192, 168, 127, 2],
            host_ip: [192, 168, 127, 254],
            netmask: [255, 255, 255, 0],
            port: 9002,
            tcp_tester: TcpTester::new(9002),
            #[cfg(feature = "host")]
            should_run: gvproxy::should_run,
            #[cfg(feature = "host")]
            setup_backend: gvproxy::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32, Test, TestSetup};
    use krun_sys::*;
    use std::thread;

    impl Test for TestNet {
        fn should_run(&self) -> ShouldRun {
            if unsafe { krun_call_u32!(krun_has_feature(KRUN_FEATURE_NET.into())) }.ok() != Some(1) {
                return ShouldRun::No("libkrun compiled without NET");
            }
            (self.should_run)()
        }

        fn check(self: Box<Self>, child: std::process::Child) -> crate::TestOutcome {
            let output = child.wait_with_output().unwrap();
            if let Some(cleanup) = self.cleanup {
                cleanup();
            }
            if String::from_utf8(output.stdout).unwrap() == "OK\n" {
                crate::TestOutcome::Pass
            } else {
                crate::TestOutcome::Fail
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // Start TCP server
            let tcp_tester = self.tcp_tester.clone();
            let listener = tcp_tester.create_server_socket();
            thread::spawn(move || tcp_tester.run_server(listener));

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;

                // Backend-specific setup
                (self.setup_backend)(ctx, &test_setup)?;

                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::net_config::configure_interface;
    use crate::Test;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;

    fn expect_msg(stream: &mut TcpStream, expected: &[u8]) {
        let mut buf = vec![0; expected.len()];
        stream.read_exact(&mut buf[..]).unwrap();
        assert_eq!(&buf[..], expected);
    }

    fn set_timeouts(stream: &mut TcpStream) {
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    }

    impl Test for TestNet {
        fn in_guest(self: Box<Self>) {
            // Configure eth0 with static IP
            configure_interface("eth0", self.guest_ip, self.netmask)
                .expect("Failed to configure eth0");

            // Connect to host TCP server
            let host_ip = self.host_ip;
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(host_ip[0], host_ip[1], host_ip[2], host_ip[3])),
                self.port,
            );

            // Retry connection a few times since network may take time to come up
            let mut stream = None;
            for _ in 0..10 {
                match TcpStream::connect(addr) {
                    Ok(s) => {
                        stream = Some(s);
                        break;
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            }
            let mut stream = stream.expect("Failed to connect to host");
            set_timeouts(&mut stream);

            // Run the TCP test protocol
            expect_msg(&mut stream, b"ping!");
            stream.write_all(b"pong!").unwrap();
            expect_msg(&mut stream, b"bye!");

            println!("OK");
        }
    }
}

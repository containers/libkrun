//! Unified virtio-net integration tests
//!
//! All tests follow the same pattern:
//! 1. Host: Start backend + TCP server
//! 2. Guest: Connect to host TCP server (eth0 configured via DHCP by init)

use crate::tcp_tester::TcpTester;
use macros::{guest, host};

#[host]
use crate::{ShouldRun, TestSetup};

#[cfg(feature = "host")]
pub(crate) mod gvproxy;
#[cfg(feature = "host")]
pub(crate) mod passt;
#[cfg(feature = "host")]
pub(crate) mod tap;
#[cfg(feature = "host")]
pub(crate) mod vmnet_helper;

/// Virtio-net test with configurable backend
pub struct TestNet {
    tcp_tester: TcpTester,
    #[cfg(feature = "host")]
    should_run: fn() -> ShouldRun,
    #[cfg(feature = "host")]
    setup_backend: fn(&TestSetup) -> anyhow::Result<krun::NetDevice>,
    #[cfg(feature = "host")]
    cleanup: Option<fn()>,
}

impl TestNet {
    pub fn new_passt() -> Self {
        Self {
            tcp_tester: TcpTester::new([169, 254, 2, 2].into(), 9000),
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
            tcp_tester: TcpTester::new([10, 0, 0, 1].into(), 9001),
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
            tcp_tester: TcpTester::new([192, 168, 127, 254].into(), 9002),
            #[cfg(feature = "host")]
            should_run: gvproxy::should_run,
            #[cfg(feature = "host")]
            setup_backend: gvproxy::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    /// Gvproxy backend variant with a socket path ≥ 96 bytes, triggering the
    /// ENAMETOOLONG bug when the local socket was derived from the peer path.
    pub fn new_gvproxy_long_path() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 168, 127, 254].into(), 9004),
            #[cfg(feature = "host")]
            should_run: gvproxy::should_run,
            #[cfg(feature = "host")]
            setup_backend: gvproxy::setup_backend_long_path,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_vmnet_helper() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 168, 105, 1].into(), 9003),
            #[cfg(feature = "host")]
            should_run: vmnet_helper::should_run,
            #[cfg(feature = "host")]
            setup_backend: vmnet_helper::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::VmConfig;
    use crate::{Test, TestOutcome, TestSetup};
    use krun::NetDevice;
    use std::thread;

    impl Test for TestNet {
        fn should_run(&self) -> ShouldRun {
            if !cfg!(feature = "net") {
                return ShouldRun::No("libkrun compiled without NET");
            }
            (self.should_run)()
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            if let Some(cleanup) = self.cleanup {
                cleanup();
            }
            let output = String::from_utf8(stdout).unwrap();
            if output == "OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!("expected exactly {:?}, got {:?}", "OK\n", output))
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let tcp_tester = self.tcp_tester;
            let listener = tcp_tester.create_server_socket();
            thread::spawn(move || tcp_tester.run_server(listener));

            let net_device = (self.setup_backend)(&test_setup)?;

            let mut vm_config = VmConfig::new_with_init(1, 512, &test_setup, |b| b.dhcp(true))?;
            vm_config.devices.add(net_device);
            vm_config.build_and_run()
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    impl Test for TestNet {
        fn in_guest(self: Box<Self>) {
            self.tcp_tester.run_client();

            println!("OK");
        }
    }
}

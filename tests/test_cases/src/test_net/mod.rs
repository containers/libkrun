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
pub(crate) mod gvproxy;
#[cfg(feature = "host")]
pub(crate) mod passt;
#[cfg(feature = "host")]
pub(crate) mod tap;
#[cfg(feature = "host")]
pub(crate) mod vmnet_helper;

/// Virtio-net test with configurable backend
pub struct TestNet {
    #[cfg(feature = "guest")]
    guest_ip: [u8; 4],
    #[cfg(feature = "guest")]
    netmask: [u8; 4],
    #[cfg(feature = "guest")]
    gateway: Option<[u8; 4]>,
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
            #[cfg(feature = "guest")]
            guest_ip: [169, 254, 2, 1],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 0, 0],
            #[cfg(feature = "guest")]
            gateway: None,
            tcp_tester: TcpTester::new(9000, [169, 254, 2, 2].into()),
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
            #[cfg(feature = "guest")]
            guest_ip: [10, 0, 0, 2],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 255, 0],
            #[cfg(feature = "guest")]
            gateway: None,
            tcp_tester: TcpTester::new(9001, [10, 0, 0, 1].into()),
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
            #[cfg(feature = "guest")]
            guest_ip: [192, 168, 127, 2],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 255, 0],
            #[cfg(feature = "guest")]
            gateway: None,
            tcp_tester: TcpTester::new(9002, [192, 168, 127, 254].into()),
            #[cfg(feature = "host")]
            should_run: gvproxy::should_run,
            #[cfg(feature = "host")]
            setup_backend: gvproxy::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_vmnet_helper() -> Self {
        Self {
            #[cfg(feature = "guest")]
            guest_ip: [192, 168, 105, 2],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 255, 0],
            #[cfg(feature = "guest")]
            gateway: Some([192, 168, 105, 1]),
            // HACK: hardcoded host LAN IP for testing; guest needs a default
            // route via the vmnet gateway (192.168.105.1) to reach it.
            tcp_tester: TcpTester::new(9003, [10, 42, 0, 115].into()),
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
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32, Test, TestSetup};
    use krun_sys::*;
    use std::thread;

    impl Test for TestNet {
        fn should_run(&self) -> ShouldRun {
            if unsafe { krun_call_u32!(krun_has_feature(KRUN_FEATURE_NET.into())) }.ok() != Some(1)
            {
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
            let tcp_tester = self.tcp_tester;
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

    impl Test for TestNet {
        fn in_guest(self: Box<Self>) {
            configure_interface("eth0", self.guest_ip, self.netmask)
                .expect("Failed to configure eth0");

            if let Some(gw) = self.gateway {
                crate::net_config::add_default_route(gw)
                    .expect("Failed to add default route");
            }

            self.tcp_tester.run_client();

            println!("OK");
        }
    }
}

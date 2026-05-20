use crate::tcp_tester::TcpTester;
use macros::{guest, host};
use std::net::Ipv4Addr;

const PORT: u16 = 8000;

pub struct TestFreeBsdGvproxyTcpGuestListen {
    tcp_tester: TcpTester,
}

impl TestFreeBsdGvproxyTcpGuestListen {
    pub fn new() -> TestFreeBsdGvproxyTcpGuestListen {
        // The host-side client connects to 127.0.0.1:PORT — gvproxy's port-forward
        // rule maps that to GUEST_IP:PORT inside the virtual network.
        Self {
            tcp_tester: TcpTester::new(Ipv4Addr::new(127, 0, 0, 1), PORT),
        }
    }
}

#[host]
mod host {
    use super::*;

    use crate::common_freebsd::{
        freebsd_assets, normalize_serial_output, setup_gvproxy_backend, setup_kernel_and_enter,
    };
    use crate::test_net::gvproxy::{gvproxy_path, setup_gvproxy_port_forward};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    use crate::{krun_call, krun_call_u32};
    use krun_sys::*;
    use std::net::Ipv4Addr;
    use std::thread;

    // Virtual IP assigned to the guest inside gvproxy's network.
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 2);

    impl Test for TestFreeBsdGvproxyTcpGuestListen {
        fn should_run(&self) -> ShouldRun {
            if freebsd_assets().is_none() {
                return ShouldRun::No("freebsd assets missing");
            }
            match gvproxy_path() {
                Some(_) => ShouldRun::Yes,
                None => ShouldRun::No("gvproxy not installed"),
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let assets = freebsd_assets().expect("freebsd assets must be available");

            unsafe {
                krun_call!(krun_init_log(
                    KRUN_LOG_TARGET_DEFAULT,
                    KRUN_LOG_LEVEL_TRACE,
                    KRUN_LOG_STYLE_AUTO,
                    0
                ))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                let net_sock = setup_gvproxy_backend(ctx, &test_setup)?;

                // Set up port-forwarding: host :PORT → guest GUEST_IP:PORT.
                // The guest IP (192.168.127.2) is virtual and not reachable directly from
                // the host; gvproxy's forwarder bridges the gap.
                setup_gvproxy_port_forward(&net_sock, PORT, GUEST_IP)?;

                // Spawn host-side client. Runs concurrently with the VM; retries
                // connect+first-read until the guest is listening (see TcpTester::run_client).
                let tcp_tester = self.tcp_tester;
                thread::spawn(move || {
                    tcp_tester.run_client();
                });

                setup_kernel_and_enter(ctx, test_setup, assets)?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let output_str = normalize_serial_output(stdout);
            if output_str == "OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!(
                    "expected exactly {:?}, got {:?}",
                    "OK\n", output_str
                ))
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use crate::freebsd_network::configure_virtio_net_ip;

    impl Test for TestFreeBsdGvproxyTcpGuestListen {
        fn in_guest(self: Box<Self>) {
            configure_virtio_net_ip();
            self.tcp_tester
                .run_server(self.tcp_tester.create_server_socket());
            println!("OK");
        }
    }
}

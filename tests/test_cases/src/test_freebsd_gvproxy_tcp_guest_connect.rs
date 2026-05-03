use crate::tcp_tester::TcpTester;
use macros::{guest, host};
use std::net::Ipv4Addr;

const PORT: u16 = 8000;
// gvproxy's default NAT table maps HostIP (192.168.127.254) → 127.0.0.1 on the host.
// The gateway IP (192.168.127.1) is only virtual inside gvproxy's netstack and NOT
// reachable via net.Dial from the host — connecting to it gets a TCP RST.
const HOST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 254);

pub struct TestFreeBsdGvproxyTcpGuestConnect {
    tcp_tester: TcpTester,
}

impl TestFreeBsdGvproxyTcpGuestConnect {
    pub fn new() -> TestFreeBsdGvproxyTcpGuestConnect {
        Self {
            tcp_tester: TcpTester::new(HOST_IP, PORT),
        }
    }
}

#[host]
mod host {
    use super::*;

    use crate::common_freebsd::{
        freebsd_assets, normalize_serial_output, setup_gvproxy_backend, setup_kernel_and_enter,
    };
    use crate::test_net::gvproxy::gvproxy_with_vfkit;
    use crate::{krun_call, krun_call_u32};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    use krun_sys::*;
    use std::thread;

    impl Test for TestFreeBsdGvproxyTcpGuestConnect {
        fn should_run(&self) -> ShouldRun {
            if freebsd_assets().is_none() {
                return ShouldRun::No("freebsd assets missing");
            }
            match gvproxy_with_vfkit() {
                Ok(_) => ShouldRun::Yes,
                Err(reason) => ShouldRun::No(reason),
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let assets = freebsd_assets().expect("freebsd assets must be available");

            // Spawn host-side TCP server. Guest connects to HOST_IP:PORT through gvproxy.
            let listener = self.tcp_tester.create_server_socket();
            thread::spawn(move || self.tcp_tester.run_server(listener));

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                setup_gvproxy_backend(ctx, &test_setup)?;
                setup_kernel_and_enter(ctx, test_setup, assets)?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>) -> TestOutcome {
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
    use crate::freebsd_network::configure_virtio_net_ip;
    use crate::Test;

    impl Test for TestFreeBsdGvproxyTcpGuestConnect {
        fn in_guest(self: Box<Self>) {
            configure_virtio_net_ip();
            self.tcp_tester.run_client();
            println!("OK");
        }
    }
}

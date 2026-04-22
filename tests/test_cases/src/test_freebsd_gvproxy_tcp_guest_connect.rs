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
            tcp_tester: TcpTester::new_with_ip(PORT, HOST_IP),
        }
    }
}

#[host]
mod host {
    use super::*;

    use crate::common_freebsd::{
        freebsd_assets, gvproxy_path, gvproxy_socket_paths, normalize_serial_output,
        setup_kernel_and_enter_with_gvproxy, start_gvproxy,
    };
    use crate::{krun_call, krun_call_u32};
    use crate::{ShouldRun, Test, TestSetup};
    use krun_sys::*;
    use std::process::Child;
    use std::thread;

    impl Test for TestFreeBsdGvproxyTcpGuestConnect {
        fn should_run(&self) -> ShouldRun {
            match (freebsd_assets(), gvproxy_path()) {
                (Some(_), Some(_)) => ShouldRun::Yes,
                _ => ShouldRun::No("prerequisites not met"),
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let assets = freebsd_assets().expect("freebsd assets must be available");

            let listener = self.tcp_tester.create_server_socket();
            thread::spawn(move || self.tcp_tester.run_server(listener));

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                setup_kernel_and_enter_with_gvproxy(ctx, test_setup, assets)?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, child: Child, test_setup: TestSetup) {
            // gvproxy is managed here (parent/runner process) because krun_start_enter()
            // terminates the subprocess via _exit(), making any cleanup in start_vm()
            // unreachable.  Starting and killing gvproxy from check() is the only
            // reliable pattern.
            let gvproxy_bin = gvproxy_path().expect("gvproxy must be available");
            let (net_sock, vfkit_sock) = gvproxy_socket_paths(&test_setup.tmp_dir);
            let mut gvproxy_child =
                start_gvproxy(&gvproxy_bin, &net_sock, &vfkit_sock, &test_setup.tmp_dir)
                    .expect("failed to start gvproxy");

            let output = child.wait_with_output().unwrap();
            let _ = gvproxy_child.kill();
            let _ = gvproxy_child.wait();

            let output_str = normalize_serial_output(output.stdout);
            assert_eq!(output_str, "OK\n");
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

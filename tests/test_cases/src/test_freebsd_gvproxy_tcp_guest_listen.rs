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
            tcp_tester: TcpTester::new_with_ip(PORT, Ipv4Addr::new(127, 0, 0, 1)),
        }
    }
}

#[host]
mod host {
    use super::*;

    use crate::common_freebsd::{
        freebsd_assets, gvproxy_path, gvproxy_socket_paths, normalize_serial_output,
        setup_gvproxy_port_forward, setup_kernel_and_enter_with_gvproxy, start_gvproxy,
    };
    use crate::{krun_call, krun_call_u32};
    use crate::{ShouldRun, Test, TestSetup};
    use krun_sys::*;
    use std::net::Ipv4Addr;
    use std::process::Child;
    use std::thread;
    use std::time::Duration;

    // Virtual IP assigned to the guest inside gvproxy's network.
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 2);

    impl Test for TestFreeBsdGvproxyTcpGuestListen {
        fn should_run(&self) -> ShouldRun {
            match (freebsd_assets(), gvproxy_path()) {
                (Some(_), Some(_)) => ShouldRun::Yes,
                _ => ShouldRun::No("prerequisites not met"),
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let assets = freebsd_assets().expect("freebsd assets must be available");

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

            // Set up port-forwarding: host :PORT → guest GUEST_IP:PORT.
            // The guest IP (192.168.127.2) is virtual and not reachable directly from
            // the host; gvproxy's forwarder bridges the gap.
            setup_gvproxy_port_forward(&net_sock, PORT, GUEST_IP)
                .expect("failed to set up gvproxy port forward");

            // Spawn the host-side client.  It must run in the parent process — spawning
            // it in start_vm() (child) would kill it when krun_start_enter() calls
            // _exit().  The connect() helper retries up to 5 times, giving the guest
            // time to start listening.
            let tcp_tester = self.tcp_tester;
            thread::spawn(move || {
                // TODO: debug gvproxy timing issue
                // if we don't wait here, reading mesages
                // in run_client leads to unexpected EOF
                // and retrying doesn't help at that point
                thread::sleep(Duration::from_secs(2));
                tcp_tester.run_client();
            });

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

    impl Test for TestFreeBsdGvproxyTcpGuestListen {
        fn in_guest(self: Box<Self>) {
            configure_virtio_net_ip();
            self.tcp_tester
                .run_server(self.tcp_tester.create_server_socket());
            println!("OK");
        }
    }
}

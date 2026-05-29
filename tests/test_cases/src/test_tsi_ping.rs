use macros::{guest, host};

pub struct TestTsiPing;

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    use krun_sys::*;

    const CONTAINERFILE: &str = "\
FROM fedora:44
RUN dnf install -y iputils && dnf clean all
";

    impl Test for TestTsiPing {
        fn rootfs_image(&self) -> Option<&'static str> {
            Some(CONTAINERFILE)
        }

        fn should_run(&self) -> ShouldRun {
            ShouldRun::Yes
        }

        fn timeout_secs(&self) -> u64 {
            30
        }

        fn needs_host_network(&self) -> bool {
            true
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let output = String::from_utf8(stdout).unwrap_or_default();
            if output == "OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!("expected {:?}, got {:?}", "OK\n", output))
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::process::Command;

    impl Test for TestTsiPing {
        fn in_guest(self: Box<Self>) {
            // Ping an external address so the guest kernel can't satisfy it
            // locally — forces the TSI vsock proxy path.  Without the
            // protocol fix, TSI creates a UDP socket and ping times out.
            let output = Command::new("/usr/bin/ping")
                .args(["-c", "3", "-W", "2", "8.8.8.8"])
                .output()
                .expect("Failed to run ping");

            if output.status.success() {
                println!("OK");
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                panic!(
                    "ping failed (exit={}):\nstdout: {}\nstderr: {}",
                    output.status, stdout, stderr
                );
            }
        }
    }
}

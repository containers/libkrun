use macros::{guest, host};

pub struct TestFreeBsdBoot;

#[host]
mod host {
    use super::*;

    use crate::common_freebsd::{freebsd_assets, normalize_serial_output, setup_kernel_and_enter};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup, krun_call, krun_call_u32};
    use krun_sys::*;

    impl Test for TestFreeBsdBoot {
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

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let assets = freebsd_assets().expect("FreeBSD assets must be present when test runs");
            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                setup_kernel_and_enter(ctx, test_setup, assets)?;
            }
            Ok(())
        }

        fn should_run(&self) -> ShouldRun {
            match freebsd_assets() {
                Some(_) => ShouldRun::Yes,
                None => ShouldRun::No("freebsd assets missing"),
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;

    use crate::Test;

    impl Test for TestFreeBsdBoot {
        fn in_guest(self: Box<Self>) {
            println!("OK");
        }
    }
}

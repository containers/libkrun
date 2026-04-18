use macros::{guest, host};

pub struct TestFreeBsdBoot;

#[host]
mod host {
    use super::*;

    use std::process::Child;

    use crate::common_freebsd::{freebsd_assets, normalize_serial_output, setup_kernel_and_enter};
    use crate::{krun_call, krun_call_u32, ShouldRun, Test, TestSetup};
    use krun_sys::*;

    impl Test for TestFreeBsdBoot {
        fn check(self: Box<Self>, child: Child, _test_setup: TestSetup) {
            let output = child.wait_with_output().unwrap();
            let output_str = normalize_serial_output(output.stdout);
            assert_eq!(output_str, "OK\n");
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
                None => ShouldRun::No("prerequisites not met"),
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

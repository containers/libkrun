use macros::{guest, host};

pub struct TestExecNullEnvp;

#[host]
mod host {
    use super::*;

    use crate::common::setup_fs_and_enter_with_envp;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;

    impl Test for TestExecNullEnvp {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 256))?;
                setup_fs_and_enter_with_envp(ctx, test_setup, std::ptr::null())?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    impl Test for TestExecNullEnvp {
        fn in_guest(self: Box<Self>) {
            println!("OK");
        }
    }
}

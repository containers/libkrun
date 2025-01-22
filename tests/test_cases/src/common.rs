//! Common utilities used by multiple test

use anyhow::Context;
use std::ffi::CString;
use std::fs;
use std::fs::create_dir;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null;

use crate::{krun_call, TestSetup};
use krun_sys::*;

fn copy_guest_agent(dir: &Path) -> anyhow::Result<()> {
    let path = std::env::var_os("KRUN_TEST_GUEST_AGENT_PATH")
        .context("KRUN_TEST_GUEST_AGENT_PATH env variable not set")?;

    let output_path = dir.join("guest-agent");
    fs::copy(path, output_path).context("Failed to copy executable into vm")?;
    Ok(())
}

/// Common part of most test. This setups an empty root filesystem, copies the guest agent there
/// and runs the guest agent in the VM.
/// Note that some tests might want to use a different root file system (perhaps a qcow image),
/// in which case the test can implement the equivalent functionality itself, or better if there
/// are more test doing that, add another utility method in this file.
///
/// The returned object is used for deleting the temporary files.
pub fn setup_fs_and_enter(ctx: u32, test_setup: TestSetup) -> anyhow::Result<()> {
    let root_dir = test_setup.tmp_dir.join("root");
    create_dir(&root_dir).context("Failed to create root directory")?;

    let path_str = CString::new(root_dir.as_os_str().as_bytes()).context("CString::new")?;
    copy_guest_agent(&root_dir)?;
    unsafe {
        krun_call!(krun_set_root(ctx, path_str.as_ptr()))?;
        krun_call!(krun_set_workdir(ctx, c"/".as_ptr()))?;
        let test_case_cstr = CString::new(test_setup.test_case).context("CString::new")?;
        let argv = [test_case_cstr.as_ptr(), null()];
        //let envp = [c"RUST_BACKTRACE=1".as_ptr(), null()];
        let envp = [null()];
        krun_call!(krun_set_exec(
            ctx,
            c"/guest-agent".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
        ))?;
        krun_call!(krun_start_enter(ctx))?;
    }
    unreachable!()
}

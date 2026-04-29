//! Common utilities used by multiple test

use anyhow::Context;
use std::ffi::{c_char, CStr, CString};
use std::fs;
use std::fs::create_dir;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
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

/// Creates the root filesystem directory and copies the guest agent into it.
/// Returns the path to the root directory. Use this when you need to configure the root
/// filesystem yourself (e.g. via `krun_add_virtiofs3` for read-only mounts) rather than
/// using the default `setup_fs_and_enter`.
pub fn setup_rootfs(test_setup: &TestSetup) -> anyhow::Result<PathBuf> {
    let root_dir = test_setup.tmp_dir.join("rootfs");
    if !root_dir.exists() {
        create_dir(&root_dir).context("Failed to create rootfs directory")?;
    }
    copy_guest_agent(&root_dir)?;
    Ok(root_dir)
}

/// Sets up the root filesystem, copies the guest agent into it, and enters the VM.
pub fn setup_fs_and_enter(ctx: u32, test_setup: TestSetup) -> anyhow::Result<()> {
    setup_fs_and_enter_with_env(ctx, test_setup, &[])
}

pub fn setup_fs_and_enter_with_env(
    ctx: u32,
    test_setup: TestSetup,
    guest_env: &[&CStr],
) -> anyhow::Result<()> {
    let root_dir = setup_rootfs(&test_setup)?;

    let path_str = CString::new(root_dir.as_os_str().as_bytes()).context("CString::new")?;
    let mut envp: Vec<*const c_char> = guest_env
        .iter()
        .map(|entry| entry.as_ptr().cast())
        .collect();
    envp.push(null());
    unsafe {
        krun_call!(krun_set_root(ctx, path_str.as_ptr()))?;
        krun_call!(krun_set_workdir(ctx, c"/".as_ptr()))?;
        let test_case_cstr = CString::new(test_setup.test_case).context("CString::new")?;
        let argv = [test_case_cstr.as_ptr(), null()];
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

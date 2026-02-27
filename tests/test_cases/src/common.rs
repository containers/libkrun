//! Common utilities used by multiple tests

use anyhow::Context;
use std::ffi::CString;
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
    std::fs::copy(path, output_path).context("Failed to copy executable into vm")?;
    Ok(())
}

/// Common setup for most tests. Sets up the root filesystem and runs the guest agent in the VM.
///
/// If `requires_namespace` is true, the runner has already created the root directory structure
/// with /dev, /tmp, /sys, guest-agent. After krun_create_ctx loads libraries, we chroot there.
///
/// If `requires_namespace` is false, this function creates a root directory, copies the
/// guest agent there, and sets it as the VM root.
pub fn setup_fs_and_enter(ctx: u32, test_setup: TestSetup) -> anyhow::Result<()> {
    let root_path = if test_setup.requires_namespace {
        // Runner set up the root dir structure, now we chroot after libraries are loaded
        use nix::mount::{mount, MsFlags};
        use nix::unistd::{chdir, chroot};

        let root_dir = test_setup.tmp_dir.join("root");

        // Chroot into the prepared root
        chroot(&root_dir).context("Failed to chroot")?;
        chdir("/").context("Failed to chdir to /")?;

        // Mount procfs after chroot
        mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .context("Failed to mount procfs")?;

        CString::new("/").context("CString::new")?
    } else {
        // Create root directory and copy guest agent
        let root_dir = test_setup.tmp_dir.join("root");
        create_dir(&root_dir).context("Failed to create root directory")?;
        // Create /tmp for tests that use Unix sockets
        let _ = create_dir(root_dir.join("tmp"));
        copy_guest_agent(&root_dir)?;
        CString::new(root_dir.as_os_str().as_bytes()).context("CString::new")?
    };

    unsafe {
        krun_call!(krun_set_root(ctx, root_path.as_ptr()))?;
        krun_call!(krun_set_workdir(ctx, c"/".as_ptr()))?;
        let test_case_cstr = CString::new(test_setup.test_case).context("CString::new")?;
        let argv = [test_case_cstr.as_ptr(), null()];
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

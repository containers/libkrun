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

use nix::unistd::{chroot, chdir};
use std::path::PathBuf;

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

/// Like setup_fs_and_enter, but changes the host process's root to the guest's root
/// before entering the VM. This is needed for Unix domain socket TSI tests where the
/// host process needs to access socket paths in the guest filesystem.
///
/// This function:
/// 1. Creates a new user namespace and mount namespace (unshare CLONE_NEWUSER | CLONE_NEWNS)
/// 2. Sets up uid/gid mappings to become root in the namespace
/// 3. Changes root to the guest's root directory (chroot)
/// 4. Then calls krun_start_enter
///
/// The before_enter callback is called after chroot but before krun_start_enter, allowing
/// setup of host-side resources (like Unix domain socket servers) that need to be accessible
/// at the same paths as the guest will use.
///
/// Note: This uses rootless namespaces (user namespaces) so it doesn't require root.
pub fn setup_fs_and_enter_with_namespace<F>(
    ctx: u32,
    test_setup: TestSetup,
    before_enter: F,
) -> anyhow::Result<()>
where
    F: FnOnce() -> anyhow::Result<()>,
{
    let root_dir = test_setup.tmp_dir.join("root");
    create_dir(&root_dir).context("Failed to create root directory")?;

    // Create necessary directories in the guest root
    create_dir(root_dir.join("tmp")).context("Failed to create tmp directory")?;
    create_dir(root_dir.join("dev")).context("Failed to create dev directory")?;
    create_dir(root_dir.join("proc")).context("Failed to create proc directory")?;
    create_dir(root_dir.join("sys")).context("Failed to create sys directory")?;

    copy_guest_agent(&root_dir)?;

    // The runner has already set up the namespace for us (user+mount+pid)
    // We are now root in the user namespace and PID 1 in the PID namespace
    // Make our mounts private so they don't affect the parent namespace
    use nix::mount::{mount, MsFlags};
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    ).context("Failed to make / private")?;

    // Bind mount /dev into the guest root so /dev/kvm is accessible
    // (we're root in the namespace now)
    mount(
        Some("/dev"),
        root_dir.join("dev").as_path(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    ).context("Failed to bind mount /dev")?;

    // Now we can chroot
    let root_path = PathBuf::from(&root_dir);
    chroot(&root_path).context("Failed to chroot to guest root")?;
    chdir("/").context("Failed to chdir to /")?;

    // Mount procfs after chroot with standard proc mount flags
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ).context("Failed to mount procfs")?;

    // Call the before_enter callback to set up host-side resources
    before_enter().context("before_enter callback failed")?;

    let path_str = CString::new("/").context("CString::new")?;
    unsafe {
        krun_call!(krun_set_root(ctx, path_str.as_ptr()))?;
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

//! Common utilities used by multiple test

use anyhow::Context;
use std::ffi::CString;
use std::fs::{self, create_dir, create_dir_all};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::null;

use crate::{krun_call, TestSetup};
use krun_sys::*;

fn copy_guest_agent(dir: &Path) -> anyhow::Result<PathBuf> {
    let path = std::env::var_os("KRUN_TEST_GUEST_AGENT_PATH")
        .context("KRUN_TEST_GUEST_AGENT_PATH env variable not set")?;

    let output_path = dir.join("guest-agent");
    fs::copy(path, &output_path).context("Failed to copy executable into vm")?;
    Ok(output_path)
}

fn guest_agent_runtime_deps(guest_agent: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let output = Command::new("ldd")
        .arg(guest_agent)
        .output()
        .context("Failed to execute ldd for guest-agent")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stderr.contains("not a dynamic executable")
            || stdout.contains("not a dynamic executable")
            || stderr.contains("statically linked")
            || stdout.contains("statically linked")
        {
            return Ok(Vec::new());
        }
        anyhow::bail!("ldd guest-agent failed: {}", stderr);
    }

    let stdout = String::from_utf8(output.stdout).context("ldd output is not utf8")?;
    let mut deps = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((_, rhs)) = line.split_once("=>") {
            let rhs = rhs.trim();
            if rhs.starts_with("not found") {
                anyhow::bail!("Missing runtime dependency: {line}");
            }
            if let Some(path) = rhs.split_whitespace().next() {
                if path.starts_with('/') {
                    deps.push(PathBuf::from(path));
                }
            }
            continue;
        }
        if let Some(path) = line.split_whitespace().next() {
            if path.starts_with('/') {
                deps.push(PathBuf::from(path));
            }
        }
    }

    deps.sort();
    deps.dedup();
    Ok(deps)
}

fn copy_host_path_into_root(root_dir: &Path, host_path: &Path) -> anyhow::Result<()> {
    let rel = host_path
        .strip_prefix("/")
        .context("runtime dependency path is not absolute")?;
    let dst = root_dir.join(rel);
    if let Some(parent) = dst.parent() {
        create_dir_all(parent).context("Failed to create parent directory in rootfs")?;
    }
    fs::copy(host_path, &dst).with_context(|| {
        format!(
            "Failed to copy runtime dependency {} into rootfs",
            host_path.display()
        )
    })?;
    Ok(())
}

fn copy_guest_agent_runtime(root_dir: &Path, guest_agent: &Path) -> anyhow::Result<()> {
    let deps = guest_agent_runtime_deps(guest_agent)?;
    for dep in deps {
        copy_host_path_into_root(root_dir, &dep)?;
    }
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
    let guest_agent = copy_guest_agent(&root_dir)?;
    copy_guest_agent_runtime(&root_dir, &guest_agent)?;
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

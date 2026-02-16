//! Passt backend for virtio-net test

use crate::{krun_call, ShouldRun, TestSetup};
use krun_sys::COMPAT_NET_FEATURES;
use nix::libc;
use std::ffi::CString;
use std::os::unix::io::RawFd;

type KrunAddNetUnixstreamFn = unsafe extern "C" fn(
    ctx_id: u32,
    c_path: *const std::ffi::c_char,
    fd: std::ffi::c_int,
    c_mac: *mut u8,
    features: u32,
    flags: u32,
) -> i32;

fn get_krun_add_net_unixstream() -> KrunAddNetUnixstreamFn {
    let symbol = CString::new("krun_add_net_unixstream").unwrap();
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
    assert!(!ptr.is_null(), "krun_add_net_unixstream not found");
    unsafe { std::mem::transmute(ptr) }
}

fn passt_available() -> bool {
    std::process::Command::new("which")
        .arg("passt")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn start_passt() -> std::io::Result<RawFd> {
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (parent_fd, child_fd) = (fds[0], fds[1]);
    let child_fd_str = child_fd.to_string();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }

    if pid == 0 {
        unsafe { libc::close(parent_fd) };
        let passt = CString::new("passt").unwrap();
        let arg_f = CString::new("-f").unwrap();
        let arg_fd = CString::new("--fd").unwrap();
        let arg_fd_val = CString::new(child_fd_str).unwrap();
        unsafe {
            libc::execlp(
                passt.as_ptr(),
                passt.as_ptr(),
                arg_f.as_ptr(),
                arg_fd.as_ptr(),
                arg_fd_val.as_ptr(),
                std::ptr::null::<libc::c_char>(),
            );
        }
        std::process::exit(1);
    }

    unsafe { libc::close(child_fd) };
    Ok(parent_fd)
}

pub(crate) fn should_run() -> ShouldRun {
    if cfg!(target_os = "macos") {
        return ShouldRun::No("passt not supported on macOS");
    }
    if !passt_available() {
        return ShouldRun::No("passt not installed");
    }
    ShouldRun::Yes
}

pub(crate) fn setup_backend(ctx: u32, _test_setup: &TestSetup) -> anyhow::Result<()> {
    let passt_fd = start_passt()?;
    let mut mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

    unsafe {
        krun_call!(get_krun_add_net_unixstream()(
            ctx,
            std::ptr::null(),
            passt_fd,
            mac.as_mut_ptr(),
            COMPAT_NET_FEATURES,
            0,
        ))?;
    }
    Ok(())
}

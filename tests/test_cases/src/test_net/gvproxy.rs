//! Gvproxy backend for virtio-net test (macOS only)

use crate::{krun_call, ShouldRun, TestSetup};
use krun_sys::{COMPAT_NET_FEATURES, NET_FLAG_DHCP_CLIENT, NET_FLAG_VFKIT};
use nix::libc;
use std::ffi::CString;

type KrunAddNetUnixgramFn = unsafe extern "C" fn(
    ctx_id: u32,
    c_path: *const std::ffi::c_char,
    fd: i32,
    c_mac: *mut u8,
    features: u32,
    flags: u32,
) -> i32;

fn get_krun_add_net_unixgram() -> KrunAddNetUnixgramFn {
    let symbol = CString::new("krun_add_net_unixgram").unwrap();
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
    assert!(!ptr.is_null(), "krun_add_net_unixgram not found");
    unsafe { std::mem::transmute(ptr) }
}

const GVPROXY_PATH: &str = match option_env!("GVPROXY_PATH") {
    Some(path) => path,
    None => "/opt/homebrew/opt/podman/libexec/podman/gvproxy",
};

fn gvproxy_path() -> Option<&'static str> {
    std::path::Path::new(GVPROXY_PATH)
        .exists()
        .then_some(GVPROXY_PATH)
}

fn start_gvproxy(
    socket_path: &str,
    log_path: &std::path::Path,
) -> std::io::Result<std::process::Child> {
    use std::process::{Command, Stdio};

    let gvproxy = gvproxy_path().expect("gvproxy not found");

    let log_file = std::fs::File::create(log_path)?;

    Command::new(gvproxy)
        .arg("--listen-vfkit")
        .arg(format!("unixgram:{}", socket_path))
        .arg("-debug")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
}

fn wait_for_socket(path: &std::path::Path, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < timeout_ms as u128 {
        if path.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

pub(crate) fn should_run() -> ShouldRun {
    #[cfg(not(target_os = "macos"))]
    return ShouldRun::No("gvproxy unixgram only supported on macOS");

    #[cfg(target_os = "macos")]
    {
        if gvproxy_path().is_none() {
            return ShouldRun::No("gvproxy not installed");
        }
        ShouldRun::Yes
    }
}

fn setup_backend_with_socket(
    ctx: u32,
    test_setup: &TestSetup,
    socket_name: &str,
    log_name: &str,
) -> anyhow::Result<()> {
    let tmp_dir = test_setup
        .tmp_dir
        .canonicalize()
        .unwrap_or_else(|_| test_setup.tmp_dir.clone());
    let socket_path = tmp_dir.join(socket_name);
    let gvproxy_log = tmp_dir.join(log_name);

    let socket_path_str = socket_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("gvproxy socket path is not valid UTF-8"))?;
    let gvproxy_child = start_gvproxy(socket_path_str, &gvproxy_log)?;
    test_setup.register_cleanup_pid(gvproxy_child.id());

    anyhow::ensure!(
        wait_for_socket(&socket_path, 5000),
        "gvproxy failed to create socket"
    );

    let mut mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
    let c_socket_path = CString::new(socket_path_str)?;

    unsafe {
        krun_call!(get_krun_add_net_unixgram()(
            ctx,
            c_socket_path.as_ptr(),
            -1,
            mac.as_mut_ptr(),
            COMPAT_NET_FEATURES,
            NET_FLAG_VFKIT | NET_FLAG_DHCP_CLIENT,
        ))?;
    }
    Ok(())
}

pub(crate) fn setup_backend(ctx: u32, test_setup: &TestSetup) -> anyhow::Result<()> {
    setup_backend_with_socket(ctx, test_setup, "gvproxy.sock", "gvproxy.log")
}

/// Backend setup with a peer socket path long enough to have previously
/// triggered ENAMETOOLONG on macOS when the local bind address was derived
/// from the peer path by appending a suffix.
pub(crate) fn setup_backend_long_path(ctx: u32, test_setup: &TestSetup) -> anyhow::Result<()> {
    // Build a peer socket filename so that the full path approaches the
    // 104-byte macOS unix socket limit. Use base_len measured at runtime so
    // the padding is correct regardless of the exact tmp_dir length.
    // tmp_dir is typically "/tmp/libkrun-tests.XXXXXXXX" (~27 chars), or
    // "/private/tmp/libkrun-tests.XXXXXXXX" (~35 chars) after canonicalize on macOS.
    let tmp_dir = test_setup
        .tmp_dir
        .canonicalize()
        .unwrap_or_else(|_| test_setup.tmp_dir.clone());
    let base_len = tmp_dir.to_str().map(|s| s.len()).unwrap_or(0);
    const TARGET_PATH_LEN: usize = 96;
    let prefix = "gvp-";
    let suffix = ".sock";
    let name_needed = TARGET_PATH_LEN.saturating_sub(base_len + 1);
    let pad_len = name_needed
        .saturating_sub(prefix.len() + suffix.len())
        .max(1);
    let socket_name = format!("{}{}{}", prefix, "x".repeat(pad_len), suffix);

    setup_backend_with_socket(ctx, test_setup, &socket_name, "gvproxy-long-path.log")
}

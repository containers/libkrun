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

pub(crate) fn setup_backend(ctx: u32, test_setup: &TestSetup) -> anyhow::Result<()> {
    let tmp_dir = test_setup
        .tmp_dir
        .canonicalize()
        .unwrap_or_else(|_| test_setup.tmp_dir.clone());
    let socket_path = tmp_dir.join("gvproxy.sock");
    let gvproxy_log = tmp_dir.join("gvproxy.log");

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

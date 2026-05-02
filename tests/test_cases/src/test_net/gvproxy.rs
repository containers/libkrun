//! Gvproxy backend for virtio-net tests.

use crate::test_net::get_krun_add_net_unixgram;
use crate::{krun_call, ShouldRun, TestSetup};
use anyhow::Context;
use krun_sys::{COMPAT_NET_FEATURES, NET_FLAG_DHCP_CLIENT, NET_FLAG_VFKIT};
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

/// Read gvproxy binary path from `KRUN_TEST_GVPROXY_PATH` (set by `tests/run.sh`).
/// Returns `None` if the variable is unset or the referenced file doesn't exist.
pub(crate) fn gvproxy_path() -> Option<PathBuf> {
    let path = std::env::var_os("KRUN_TEST_GVPROXY_PATH")?;
    let p = PathBuf::from(path);
    p.exists().then_some(p)
}

/// Resolve the gvproxy binary and confirm it accepts `--listen-vfkit unixgram:<path>`.
///
/// gvproxy ≤ v0.8.8 ships the `--listen-vfkit` flag but rejects the `unixgram` scheme
/// at runtime with `vfkit listen error: unsupported 'unixgram' scheme`; the patch
/// that lifts that restriction landed upstream as commit `c09fb7d` (post-v0.8.8).
/// Probe once per process by parsing `gvproxy -version` output:
///
/// - `gvproxy version vX.Y.Z` — accept iff (X,Y,Z) > (0,8,8).
/// - `gvproxy version gitXXXXXXX` (or anything without a `v` tag) — accept; treated
///   as a custom build assumed to include the patch (the fork builds CI uses,
///   plus future tagged releases that haven't landed yet).
///
/// The result is cached via `OnceLock` so repeated test invocations don't re-spawn
/// gvproxy.
pub(crate) fn gvproxy_with_vfkit() -> Result<PathBuf, &'static str> {
    static SUPPORTS_VFKIT: OnceLock<bool> = OnceLock::new();

    let bin = gvproxy_path().ok_or("gvproxy not installed")?;
    let ok = *SUPPORTS_VFKIT.get_or_init(|| {
        let Ok(out) = Command::new(&bin).arg("-version").output() else {
            return false;
        };
        std::str::from_utf8(&out.stdout)
            .map(version_supports_vfkit)
            .unwrap_or(false)
    });
    if !ok {
        return Err("gvproxy lacks --listen-vfkit unixgram support (need newer release)");
    }
    Ok(bin)
}

fn version_supports_vfkit(output: &str) -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    let line = output.trim();
    let v = line.strip_prefix("gvproxy version ").unwrap_or(line);
    let Some(tag) = v.strip_prefix('v') else {
        // git* or anything else: assume a custom build that includes the patch.
        return true;
    };
    let (triple, has_suffix) = parse_semver_triple(tag);
    match triple {
        Some(t) if t > (0, 8, 8) => true,
        // gvproxy's Makefile uses `git describe --always --dirty`, which produces
        // `vX.Y.Z-N-gHASH` for builds N commits past tag X.Y.Z — so a suffix on
        // the tagged version means there are extra commits past v0.8.8.
        Some(t) if t == (0, 8, 8) && has_suffix => true,
        _ => false,
    }
}

/// Parse the `MAJOR.MINOR.PATCH` triple at the start of a version string. Returns
/// the triple and a flag indicating whether trailing pre-release / build metadata
/// (e.g. `-N-gHASH` or `+build`) was present.
fn parse_semver_triple(s: &str) -> (Option<(u32, u32, u32)>, bool) {
    let (triple_part, has_suffix) = match s.find(['-', '+']) {
        Some(i) => (&s[..i], true),
        None => (s, false),
    };
    let mut it = triple_part.split('.');
    let major = it.next().and_then(|x| x.parse().ok());
    let minor = it.next().and_then(|x| x.parse().ok());
    let patch = it.next().and_then(|x| x.parse().ok());
    if it.next().is_some() {
        return (None, has_suffix);
    }
    match (major, minor, patch) {
        (Some(a), Some(b), Some(c)) => (Some((a, b, c)), has_suffix),
        _ => (None, has_suffix),
    }
}

#[cfg(test)]
mod version_tests {
    use super::version_supports_vfkit;

    #[test]
    fn accepts_known_good_versions() {
        // The CI build pinned at containers/gvisor-tap-vsock@c09fb7d:
        assert!(version_supports_vfkit(
            "gvproxy version v0.8.8-57-gc09fb7d0"
        ));
        assert!(version_supports_vfkit("gvproxy version git84b27674"));
        assert!(version_supports_vfkit("gvproxy version v0.9.0"));
        assert!(version_supports_vfkit("gvproxy version v1.0.0"));
        assert!(version_supports_vfkit("gvproxy version v0.8.9"));
    }

    #[test]
    fn rejects_known_bad_versions() {
        assert!(!version_supports_vfkit("gvproxy version v0.8.8"));
        assert!(!version_supports_vfkit("gvproxy version v0.8.7"));
        assert!(!version_supports_vfkit("gvproxy version v0.7.0"));
        // Pre-v0.8.8 tag with post-tag suffix is still pre-v0.8.8.
        assert!(!version_supports_vfkit(
            "gvproxy version v0.8.7-99-gabcdef0"
        ));
    }

    #[test]
    fn rejects_garbage() {
        assert!(!version_supports_vfkit("gvproxy version vNot.a.semver"));
    }
}

pub(crate) struct Gvproxy<'a> {
    vfkit_sock: &'a str,
    log_path: &'a Path,
    net_sock: Option<&'a str>,
    ssh_port: Option<i32>,
}

impl<'a> Gvproxy<'a> {
    pub fn new(vfkit_sock: &'a str, log_path: &'a Path) -> Self {
        Self {
            vfkit_sock,
            log_path,
            net_sock: None,
            ssh_port: None,
        }
    }

    /// Add `--listen unix://<path>` so callers can hit the HTTP API
    /// (e.g. [`setup_gvproxy_port_forward`]).
    pub fn net_sock(&mut self, net_sock: &'a str) -> &mut Self {
        self.net_sock = Some(net_sock);
        self
    }

    /// Add `--ssh-port <n>`. Pass `-1` to disable the default :22 forwarder.
    pub fn ssh_port(&mut self, ssh_port: i32) -> &mut Self {
        self.ssh_port = Some(ssh_port);
        self
    }

    pub fn start(&mut self) -> io::Result<Child> {
        let gvproxy = gvproxy_path().expect("gvproxy not found");
        let log_file = std::fs::File::create(self.log_path)?;

        let mut cmd = Command::new(gvproxy);
        cmd.arg("--listen-vfkit")
            .arg(format!("unixgram:{}", self.vfkit_sock));
        if let Some(net_sock) = self.net_sock {
            cmd.arg("--listen").arg(format!("unix://{}", net_sock));
        }
        if let Some(port) = self.ssh_port {
            cmd.arg("--ssh-port").arg(port.to_string());
        }
        cmd.arg("-debug");

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log_file)
            .spawn()
    }
}

pub(crate) fn wait_for_socket(path: &Path, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < timeout_ms as u128 {
        if path.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

/// Set up a gvproxy port-forwarding rule via its HTTP API.
///
/// Sends `POST /services/forwarder/expose` with
/// `{"local":":<port>","remote":"<remote_ip>:<port>"}` to the net unix socket.
/// Retries until gvproxy is accepting connections (up to ~10 s).
pub(crate) fn setup_gvproxy_port_forward(
    net_sock_path: &str,
    port: u16,
    remote_ip: Ipv4Addr,
) -> anyhow::Result<()> {
    let mut stream = None;
    for _ in 0..100 {
        match UnixStream::connect(net_sock_path) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    let mut stream = stream
        .ok_or_else(|| anyhow::anyhow!("gvproxy HTTP socket not ready: {}", net_sock_path))?;

    let body = format!(r#"{{"local":":{port}","remote":"{remote_ip}:{port}"}}"#);
    let request = format!(
        "POST /services/forwarder/expose HTTP/1.0\r\nHost: unix\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );

    stream
        .write_all(request.as_bytes())
        .context("write port-forward request")?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("read port-forward response")?;

    if !response.contains("200") {
        anyhow::bail!("gvproxy port-forward expose failed: {}", response);
    }

    Ok(())
}

pub(crate) fn should_run() -> ShouldRun {
    match gvproxy_with_vfkit() {
        Ok(_) => ShouldRun::Yes,
        Err(reason) => ShouldRun::No(reason),
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
    let gvproxy_child = Gvproxy::new(socket_path_str, &gvproxy_log).start()?;
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

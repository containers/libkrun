//! Gvproxy backend for virtio-net test (macOS only)

use crate::{ShouldRun, TestSetup};
use krun::{NetDevice, VirtioNetBackend};

use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

const GVPROXY_PATH: &str = match option_env!("GVPROXY_PATH") {
    Some(path) => path,
    None => "/opt/homebrew/opt/podman/libexec/podman/gvproxy",
};

pub(crate) fn gvproxy_path() -> Option<&'static str> {
    std::path::Path::new(GVPROXY_PATH)
        .exists()
        .then_some(GVPROXY_PATH)
}

/// A gvproxy process builder.
pub(crate) struct Gvproxy<'a> {
    vfkit_sock: &'a str,
    log_path: &'a Path,
    net_sock: Option<&'a str>,
    ssh_port: Option<i32>,
}

impl<'a> Gvproxy<'a> {
    pub(crate) fn new(vfkit_sock: &'a str, log_path: &'a Path) -> Self {
        Self {
            vfkit_sock,
            log_path,
            net_sock: None,
            ssh_port: None,
        }
    }

    /// Add `--listen unix://<path>` so callers can hit the HTTP API
    /// (e.g. [`setup_gvproxy_port_forward`]).
    pub(crate) fn net_sock(mut self, net_sock: &'a str) -> Self {
        self.net_sock = Some(net_sock);
        self
    }

    /// Add `--ssh-port <n>`. Pass `-1` to disable the default :22 forwarder.
    pub(crate) fn ssh_port(mut self, ssh_port: i32) -> Self {
        self.ssh_port = Some(ssh_port);
        self
    }

    pub(crate) fn start(self) -> io::Result<Child> {
        let gvproxy = gvproxy_path().expect("gvproxy not found");
        let log_file = std::fs::File::create(self.log_path)?;

        let mut cmd = Command::new(gvproxy);
        cmd.arg("--listen-vfkit")
            .arg(format!("unixgram:{}", self.vfkit_sock));
        if let Some(net_sock) = self.net_sock {
            cmd.arg("--listen").arg(format!("unix://{net_sock}"));
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
    let mut stream =
        stream.ok_or_else(|| anyhow::anyhow!("gvproxy HTTP API socket not ready after 10 s"))?;

    let body = format!(r#"{{"local":":{port}","remote":"{remote_ip}:{port}"}}"#);
    let request = format!(
        "POST /services/forwarder/expose HTTP/1.0\r\nHost: unix\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| anyhow::anyhow!("write port-forward request: {e}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| anyhow::anyhow!("read port-forward response: {e}"))?;

    if !response.contains("200") {
        anyhow::bail!("gvproxy port-forward expose failed: {}", response);
    }

    Ok(())
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

pub(crate) fn setup_backend(test_setup: &TestSetup) -> anyhow::Result<NetDevice> {
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

    let mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

    // vfkit=true for gvproxy vfkit mode
    NetDevice::new(
        "net0",
        VirtioNetBackend::UnixgramPath(socket_path, true),
        mac,
        krun::COMPAT_NET_FEATURES,
    )
    .map_err(|e| anyhow::anyhow!("net device: {e:?}"))
}

pub(crate) fn setup_backend_long_path(test_setup: &TestSetup) -> anyhow::Result<NetDevice> {
    // Build a peer socket filename so that the full path approaches the
    // 104-byte macOS unix socket limit.
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

    let socket_path = tmp_dir.join(&socket_name);
    let gvproxy_log = tmp_dir.join("gvproxy-long-path.log");

    let socket_path_str = socket_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("gvproxy socket path is not valid UTF-8"))?;
    let gvproxy_child = Gvproxy::new(socket_path_str, &gvproxy_log).start()?;
    test_setup.register_cleanup_pid(gvproxy_child.id());

    anyhow::ensure!(
        wait_for_socket(&socket_path, 5000),
        "gvproxy failed to create socket"
    );

    let mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

    NetDevice::new(
        "net0",
        VirtioNetBackend::UnixgramPath(socket_path, true),
        mac,
        krun::COMPAT_NET_FEATURES,
    )
    .map_err(|e| anyhow::anyhow!("net device: {e:?}"))
}

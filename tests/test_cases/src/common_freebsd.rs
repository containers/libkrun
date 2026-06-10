//! Host-side utilities for FreeBSD guest tests.

use anyhow::Context;
use libc;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::test_net::gvproxy::{wait_for_socket, Gvproxy};
use crate::TestSetup;
use krun::{
    BalloonDevice, BlockDevice, ConsoleDevice, KernelFormat, MmioDeviceManager, NetDevice, Payload,
    RngDevice, VirtioNetBackend, VmmBuilder,
};

pub struct FreeBsdAssets {
    pub kernel_path: PathBuf,
    pub iso_path: PathBuf,
}

/// Read FreeBSD asset paths from environment variables.
/// Returns `None` if either variable is unset or the referenced files don't exist.
pub fn freebsd_assets() -> Option<FreeBsdAssets> {
    let kernel_path = PathBuf::from(std::env::var_os("KRUN_TEST_FREEBSD_KERNEL_PATH")?);
    let iso_path = PathBuf::from(std::env::var_os("KRUN_TEST_FREEBSD_ISO_PATH")?);
    if !kernel_path.exists() || !iso_path.exists() {
        return None;
    }
    Some(FreeBsdAssets {
        kernel_path,
        iso_path,
    })
}

/// Create a `KRUN_CONFIG`-labelled ISO inside the test's tmp directory and return its path.
///
/// `init-freebsd` identifies the config disk by its ISO volume label (`/dev/iso9660/KRUN_CONFIG`),
/// not by vtbd index, so the label is mandatory.
fn create_config_iso(test_case: &str, tmp_dir: &Path) -> anyhow::Result<PathBuf> {
    let staging = tmp_dir.join("krun_config");
    std::fs::create_dir(&staging).context("create krun_config staging dir")?;

    let json = format!(r#"{{"Cmd":["/guest-agent","{test_case}"]}}"#);
    std::fs::write(staging.join("krun_config.json"), json).context("write krun_config.json")?;

    let iso_path = tmp_dir.join("krun_config.iso");
    let status = Command::new("bsdtar")
        .args([
            "cf",
            iso_path.to_str().context("config iso path is not UTF-8")?,
            "--format=iso9660",
            "--options",
            "volume-id=KRUN_CONFIG",
            "-C",
            staging
                .to_str()
                .context("config staging dir is not UTF-8")?,
            "krun_config.json",
        ])
        .status()
        .context(
            "Failed to run bsdtar — on Linux install libarchive-tools; on macOS bsdtar is built-in",
        )?;

    if !status.success() {
        anyhow::bail!("bsdtar exited with {status}");
    }
    Ok(iso_path)
}

/// Normalize serial-console line endings for FreeBSD output assertions.
///
/// FreeBSD's serial console emits CRLF (`\r\n`); strip the `\r` so that
/// test `check()` overrides can compare against plain `\n`-terminated strings.
pub fn normalize_serial_output(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n")
}

/// Generate a random MAC address for virtio-net device.
fn random_mac_address() -> [u8; 6] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut hasher = RandomState::new().build_hasher();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    hasher.write_u32(nanos);
    let hash = hasher.finish();

    [
        0x52, // Xen OUI
        0x54,
        0x00,
        ((hash >> 16) & 0xFF) as u8,
        ((hash >> 8) & 0xFF) as u8,
        (hash & 0xFF) as u8,
    ]
}

/// Start gvproxy and return a `NetDevice` and the net (HTTP-API) unix socket path.
///
/// Mirrors `crate::test_net::gvproxy::setup_backend` but with FreeBSD-specific knobs:
/// passes `--listen unix://...` so callers can drive the HTTP API
/// (e.g. `setup_gvproxy_port_forward`), disables gvproxy's default :22 forwarder, and
/// uses a random MAC.
///
/// Returns `(NetDevice, net_sock_str)` so callers can call
/// `setup_gvproxy_port_forward` afterwards if needed.
pub fn setup_gvproxy_backend(test_setup: &TestSetup) -> anyhow::Result<(NetDevice, String)> {
    // Short relative names: macOS `sockaddr_un.sun_path` is 104 bytes (max 103 usable chars),
    // so deep tmp paths plus long socket names can overflow.
    let tmp_dir = test_setup
        .tmp_dir
        .canonicalize()
        .unwrap_or_else(|_| test_setup.tmp_dir.clone());
    let net_sock = tmp_dir.join("gvproxy-net.sock");
    let vfkit_sock = tmp_dir.join("gvproxy-vfkit.sock");
    let gvproxy_log = tmp_dir.join("gvproxy.log");

    let net_sock_str = net_sock
        .to_str()
        .context("gvproxy net-sock path is not valid UTF-8")?
        .to_string();
    let vfkit_sock_str = vfkit_sock
        .to_str()
        .context("gvproxy vfkit-sock path is not valid UTF-8")?;

    let child = Gvproxy::new(vfkit_sock_str, &gvproxy_log)
        .net_sock(&net_sock_str)
        .ssh_port(-1)
        .start()?;
    test_setup.register_cleanup_pid(child.id());

    anyhow::ensure!(
        wait_for_socket(&vfkit_sock, 5000),
        "gvproxy failed to create vfkit socket"
    );

    let mac = random_mac_address();
    let net_device = NetDevice::new(
        "net0",
        VirtioNetBackend::UnixgramPath(vfkit_sock, true),
        mac,
        krun::COMPAT_NET_FEATURES,
    )
    .map_err(|e| anyhow::anyhow!("net device: {e:?}"))?;

    Ok((net_device, net_sock_str))
}

/// Boot a FreeBSD guest with `init-freebsd` and enter it.
///
/// - boots from a pre-built rootfs ISO (`vtbd0`) containing `init-freebsd` + `guest-agent`
/// - passes the test-case name via a `KRUN_CONFIG` ISO (`vtbd1`)
/// - uses a serial console (required by FreeBSD; output reaches the runner via the stdout pipe)
///
/// Any extra virtio devices (e.g. net) must be added to `extra_devices` before calling.
pub fn setup_kernel_and_enter(
    test_setup: TestSetup,
    assets: FreeBsdAssets,
    extra_devices: Vec<NetDevice>,
) -> anyhow::Result<()> {
    let config_iso = create_config_iso(&test_setup.test_case, &test_setup.tmp_dir)?;
    do_setup_and_enter(
        &assets.kernel_path,
        &assets.iso_path,
        &config_iso,
        extra_devices,
    )
}

/// Shared implementation for entering the guest.
fn do_setup_and_enter(
    kernel_path: &Path,
    rootfs_path: &Path,
    config_iso: &Path,
    extra_devices: Vec<NetDevice>,
) -> anyhow::Result<()> {
    krun::init_log(
        krun::LogTarget::Stderr,
        krun::LogLevel::Trace,
        krun::LogStyle::Auto,
    );

    // Create a pipe for serial console input to avoid a kqueue busy-spin on macOS.
    // When the runner's check() calls wait_with_output(), it closes the subprocess's
    // stdin (fd 0). On macOS/kqueue a closed-write-end pipe fires EVFILT_READ
    // continuously, spinning the serial device at ~100% CPU.  Using a fresh pipe
    // whose write end stays open until _exit() is called prevents that.
    // VmmBuilder takes ownership of the read fd via serial_input_fd(); we only
    // need to keep the write end alive, which _exit() will close for us.
    let mut pipe_fds: [libc::c_int; 2] = [-1, -1];
    let ret = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
    if ret != 0 {
        anyhow::bail!(
            "Failed to create serial input pipe: {}",
            std::io::Error::last_os_error()
        );
    }
    let serial_read_fd = pipe_fds[0];
    // pipe_fds[1] (write end) stays open until process exit — intentional.

    // Kernel cmdline: mount vtbd0 as root via cd9660 and hand off to init-freebsd.
    #[cfg(target_arch = "x86_64")]
    let (kernel_format, cmdline_prefix, flags) = (KernelFormat::Elf, "", "boot_mute=YES");
    #[cfg(not(target_arch = "x86_64"))]
    let (kernel_format, cmdline_prefix, flags) = (KernelFormat::Raw, "FreeBSD:", "-mq");

    let cmdline = format!(
        "{cmdline_prefix}vfs.root.mountfrom=cd9660:/dev/vtbd0 {flags} init_path=/init-freebsd"
    );

    let kernel_path = kernel_path.to_str().context("kernel path is not UTF-8")?;
    let kernel = Payload::load_external(kernel_path, kernel_format, &cmdline)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Build console (serial output to stdout — FreeBSD writes guest output there)
    let mut console_builder = ConsoleDevice::builder();
    console_builder
        .add_io_port("", None, Some(libc::STDOUT_FILENO))
        .context("add stdout console port")?;
    let console = console_builder.build().context("build console")?;

    let mut devices = MmioDeviceManager::new();
    devices.add(BalloonDevice::new().context("balloon")?);
    devices.add(RngDevice::new().context("rng")?);
    devices.add(console);

    // vtbd0: rootfs ISO (init-freebsd + guest-agent)
    let rootfs_str = rootfs_path
        .to_str()
        .context("rootfs path is not valid UTF-8")?;
    devices.add(BlockDevice::new("vtbd0", rootfs_str, true).context("vtbd0 block device")?);

    // vtbd1: config ISO (init-freebsd finds it by KRUN_CONFIG volume label, not vtbd index)
    let config_iso_str = config_iso
        .to_str()
        .context("config iso path is not valid UTF-8")?;
    devices.add(BlockDevice::new("vtbd1", config_iso_str, true).context("vtbd1 block device")?);

    // Extra devices (e.g. virtio-net for gvproxy tests)
    for net in extra_devices {
        devices.add(net);
    }

    let mut vmm = VmmBuilder::new()
        .vcpus(1)
        .context("vcpus")?
        .ram_mib(512)
        .context("ram")?
        .kernel(kernel)
        .devices(devices)
        .serial_input_fd(serial_read_fd)
        .build()
        .context("build vmm")?;
    vmm.run();
    Ok(())
}

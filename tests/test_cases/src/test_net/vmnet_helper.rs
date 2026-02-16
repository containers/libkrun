//! vmnet-helper backend for virtio-net test (macOS only)

use crate::{krun_call, ShouldRun, TestSetup};
use nix::libc;
use std::ffi::CString;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::io::FromRawFd;
use std::process::Command;

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

fn vmnet_helper_path() -> Option<String> {
    let paths = [
        "/opt/vmnet-helper/bin/vmnet-helper",
        "/opt/homebrew/opt/vmnet-helper/libexec/vmnet-helper",
        "/opt/homebrew/bin/vmnet-helper",
        "/usr/local/bin/vmnet-helper",
    ];
    for path in paths {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    Command::new("which")
        .arg("vmnet-helper")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}

/// Parse a MAC address string like "1e:d4:d1:27:4b:bf" into 6 bytes.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

struct VmnetConfig {
    fd: i32,
    mac: [u8; 6],
}

/// Start vmnet-helper with `--fd 3`, wait for its JSON config on stdout,
/// and return the fd + MAC address from vmnet.
///
/// Creates a `SOCK_DGRAM` socketpair, passes one end to vmnet-helper as fd 3
/// (matching what `vmnet-client` does), and returns the other end for use
/// with `krun_add_net_unixgram`.
fn start_vmnet_helper(log_path: &std::path::Path) -> std::io::Result<VmnetConfig> {
    let helper = vmnet_helper_path().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "vmnet-helper not found")
    })?;

    // Create a SOCK_DGRAM socketpair
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (our_fd, helper_fd) = (fds[0], fds[1]);

    // Create a pipe for reading vmnet-helper's stdout (JSON config)
    let mut stdout_fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(stdout_fds.as_mut_ptr()) } < 0 {
        unsafe {
            libc::close(our_fd);
            libc::close(helper_fd);
        }
        return Err(std::io::Error::last_os_error());
    }
    let (stdout_read, stdout_write) = (stdout_fds[0], stdout_fds[1]);

    let log_file = std::fs::File::create(log_path)?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(our_fd);
            libc::close(helper_fd);
            libc::close(stdout_read);
            libc::close(stdout_write);
        }
        return Err(std::io::Error::last_os_error());
    }

    if pid == 0 {
        // Child process
        unsafe {
            libc::close(our_fd);
            libc::close(stdout_read);

            // Redirect stdout to our pipe
            libc::dup2(stdout_write, 1);
            libc::close(stdout_write);

            // Redirect stderr to log file
            use std::os::unix::io::AsRawFd;
            libc::dup2(log_file.as_raw_fd(), 2);

            // Redirect stdin from /dev/null
            let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            if devnull >= 0 {
                libc::dup2(devnull, 0);
                libc::close(devnull);
            }

            // Place helper_fd at fd 3
            if helper_fd != 3 {
                libc::dup2(helper_fd, 3);
                libc::close(helper_fd);
            }

            let helper_c = CString::new(helper.as_str()).unwrap();
            let arg_fd = CString::new("--fd").unwrap();
            let arg_fd_val = CString::new("3").unwrap();
            libc::execlp(
                helper_c.as_ptr(),
                helper_c.as_ptr(),
                arg_fd.as_ptr(),
                arg_fd_val.as_ptr(),
                std::ptr::null::<libc::c_char>(),
            );
            libc::_exit(1);
        }
    }

    // Parent process
    unsafe {
        libc::close(helper_fd);
        libc::close(stdout_write);
    }

    // Read the JSON config line from vmnet-helper's stdout.
    // vmnet-helper writes a single JSON line then keeps running.
    let stdout_file = unsafe { std::fs::File::from_raw_fd(stdout_read) };
    let reader = BufReader::new(stdout_file);
    let mut config_line = String::new();
    reader
        .take(4096)
        .read_line(&mut config_line)
        .map_err(|e| std::io::Error::other(format!("failed to read vmnet-helper config: {e}")))?;

    if config_line.is_empty() {
        return Err(std::io::Error::other(
            "vmnet-helper exited without producing config",
        ));
    }

    eprintln!("vmnet-helper config: {}", config_line.trim());

    // Parse the MAC address from the JSON config.
    // The JSON looks like: {"vmnet_mac_address":"1e:d4:d1:27:4b:bf",...}
    let mac_str = config_line
        .split("\"vmnet_mac_address\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or_else(|| std::io::Error::other("vmnet_mac_address not found in config"))?;

    let mac = parse_mac(mac_str)
        .ok_or_else(|| std::io::Error::other(format!("invalid MAC address: {mac_str}")))?;

    // Increase socket buffer sizes so libkrun's Unixgram backend (which uses
    // the fd path and does NOT set these) can batch frames without drops.
    let buf_size: libc::c_int = 7 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            our_fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&buf_size) as libc::socklen_t,
        );
        libc::setsockopt(
            our_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&buf_size) as libc::socklen_t,
        );
    }

    Ok(VmnetConfig { fd: our_fd, mac })
}

pub(crate) fn should_run() -> ShouldRun {
    #[cfg(not(target_os = "macos"))]
    return ShouldRun::No("vmnet-helper only supported on macOS");

    #[cfg(target_os = "macos")]
    {
        if vmnet_helper_path().is_none() {
            return ShouldRun::No("vmnet-helper not installed");
        }
        ShouldRun::Yes
    }
}

pub(crate) fn setup_backend(ctx: u32, test_setup: &TestSetup) -> anyhow::Result<()> {
    let tmp_dir = test_setup
        .tmp_dir
        .canonicalize()
        .unwrap_or_else(|_| test_setup.tmp_dir.clone());
    let vmnet_log = tmp_dir.join("vmnet-helper.log");

    let mut config = start_vmnet_helper(&vmnet_log)?;

    unsafe {
        krun_call!(get_krun_add_net_unixgram()(
            ctx,
            std::ptr::null(),
            config.fd,
            config.mac.as_mut_ptr(),
            0, // no offloading - vmnet-helper uses raw ethernet frames
            0, // no VFKIT flag
        ))?;
    }
    Ok(())
}

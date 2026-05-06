use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::unix::fs as unix_fs;

use anyhow::Context;
use nix::errno::Errno;
use nix::mount::{self, MsFlags};
use nix::unistd;

/// Mount, treating EBUSY (already mounted) as success.
fn mount_or_busy(
    src: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: MsFlags,
) -> anyhow::Result<()> {
    match mount::mount(src, target, fstype, flags, None::<&str>) {
        Ok(()) => Ok(()),
        Err(Errno::EBUSY) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("mount {target}")),
    }
}

pub fn mount_filesystems() -> anyhow::Result<()> {
    let base_flags = MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME;
    fs::create_dir_all("/dev").context("create /dev")?;
    fs::create_dir_all("/proc").context("create /proc")?;
    fs::create_dir_all("/sys").context("create /sys")?;

    mount_or_busy(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_RELATIME,
    )?;

    mount_or_busy(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NODEV | base_flags,
    )?;

    mount_or_busy(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NODEV | base_flags,
    )?;

    mount_or_busy(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MsFlags::MS_NODEV | base_flags,
    )?;

    fs::create_dir_all("/dev/pts").context("create /dev/pts")?;
    fs::create_dir_all("/dev/shm").context("create /dev/shm")?;

    mount_or_busy(Some("devpts"), "/dev/pts", Some("devpts"), base_flags)?;
    mount_or_busy(Some("tmpfs"), "/dev/shm", Some("tmpfs"), base_flags)?;

    // Best-effort; may already exist.
    let _ = unix_fs::symlink("/proc/self/fd", "/dev/fd");

    Ok(())
}

/// Returns true if path is listed as a mount point in /proc/mounts.
///
/// Uses /proc/mounts instead of stat() because Podman arranges tmpfs
/// auto-mounts that would be triggered by a stat call.
pub fn is_mount_point(path: &str) -> bool {
    let Ok(f) = File::open("/proc/mounts") else {
        return false;
    };
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let mut parts = line.split_whitespace();
        let _ = parts.next(); // device
        if parts.next() == Some(path) {
            return true;
        }
    }
    false
}

pub fn mount_tmpfs(path: &str) -> anyhow::Result<()> {
    mount::mount(
        Some("tmpfs"),
        path,
        Some("tmpfs"),
        MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RELATIME,
        None::<&str>,
    )
    .with_context(|| format!("mount tmpfs at {path}"))
}

/// Mount /dev/vda as ext4, then pivot root into it.
#[cfg(any(feature = "amd-sev", feature = "tdx"))]
pub fn mount_tee_block_device() -> anyhow::Result<()> {
    fs::create_dir_all("/tmp/vda").context("create /tmp/vda")?;

    mount_or_busy(
        Some("/dev/vda"),
        "/tmp/vda",
        Some("ext4"),
        MsFlags::MS_RELATIME,
    )?;
    unistd::chdir("/tmp/vda").context("chdir /tmp/vda")?;

    mount_or_busy(Some("."), "/", None::<&str>, MsFlags::MS_MOVE)?;
    unistd::chroot(".").context("chroot .")
}

//! Podman-based rootfs provisioning for tests that need a full Linux rootfs.
//!
//! `build_rootfs` builds the podman image and exports a rootfs tarball to
//! `/tmp/libkrun-test-rootfs-cache/`. This runs outside any namespace
//! (via `build-images`). `extract_rootfs` just extracts the cached tarball,
//! so it works inside the `unshare --user --net` namespace without podman.

use anyhow::{bail, Context};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CACHE_DIR: &str = "/tmp/libkrun-test-rootfs-cache";

fn image_tag(name: &str) -> String {
    format!("libkrun-test-{name}")
}

fn tarball_path(name: &str) -> PathBuf {
    Path::new(CACHE_DIR).join(format!("{name}.tar"))
}

fn podman_available() -> bool {
    Command::new("podman")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Checks whether the rootfs tarball for the given name has been built.
pub fn rootfs_is_built(name: &str) -> bool {
    tarball_path(name).exists()
}

/// Builds the podman image and exports a rootfs tarball to the cache.
/// Must be called outside any namespace (needs podman + network).
pub fn build_rootfs(name: &str) -> anyhow::Result<()> {
    if !podman_available() {
        bail!("podman not installed");
    }

    let tag = image_tag(name);
    let containerfile = crate::rootfs_images()
        .iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("unknown rootfs image: {name}"))
        .1;

    // Build image (podman layer cache makes this fast when unchanged)
    let mut build = Command::new("podman")
        .args(["build", "-t", &tag, "-f", "-", "."])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning podman build")?;

    build
        .stdin
        .take()
        .unwrap()
        .write_all(containerfile.as_bytes())
        .context("writing containerfile to podman stdin")?;

    let output = build
        .wait_with_output()
        .context("waiting for podman build")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("podman build failed: {stderr}");
    }

    // Export rootfs tarball to cache
    fs::create_dir_all(CACHE_DIR).context("creating rootfs cache directory")?;

    let create_out = Command::new("podman")
        .args(["create", &tag])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("podman create")?;

    if !create_out.status.success() {
        let stderr = String::from_utf8_lossy(&create_out.stderr);
        bail!("podman create failed: {stderr}");
    }

    let ctr_id = String::from_utf8(create_out.stdout)
        .context("container id not utf-8")?
        .trim()
        .to_string();

    let tarball = tarball_path(name);
    let tar_file = fs::File::create(&tarball).context("creating rootfs tarball file")?;

    let mut export = Command::new("podman")
        .args(["export", &ctr_id])
        .stdout(tar_file)
        .stderr(Stdio::piped())
        .spawn()
        .context("podman export")?;

    let export_status = export.wait().context("waiting for podman export")?;
    let _ = Command::new("podman").args(["rm", &ctr_id]).status();

    if !export_status.success() {
        let _ = fs::remove_file(&tarball);
        bail!("podman export failed");
    }

    Ok(())
}

/// Extracts the cached rootfs tarball into `dest`.
/// The tarball must already exist (call `build_rootfs` first via `build-images`).
pub fn extract_rootfs(name: &str, dest: &Path) -> anyhow::Result<()> {
    let tarball = tarball_path(name);
    if !tarball.exists() {
        bail!("rootfs tarball not found for {name} (run build-images first)");
    }

    fs::create_dir_all(dest).context("creating rootfs destination directory")?;

    let status = Command::new("tar")
        .arg("-xf")
        .arg(&tarball)
        .arg("--no-same-owner")
        .arg("-C")
        .arg(dest)
        .status()
        .context("extracting rootfs")?;

    if !status.success() {
        bail!("tar extraction failed");
    }

    Ok(())
}

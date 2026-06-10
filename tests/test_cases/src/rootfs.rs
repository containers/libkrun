//! Podman-based rootfs provisioning for tests that need a full Linux rootfs.
//!
//! `prepare_rootfs` builds a podman image from a Containerfile string, creates a container,
//! and pipes `podman export` directly into `tar -x` to populate the destination directory.
//! The image tag is derived from the hash of the Containerfile content (`krun-test-<hash>`),
//! so podman's layer cache makes rebuilds fast when the Containerfile hasn't changed.

use anyhow::{bail, Context};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn containerfile_tag(containerfile: &str) -> anyhow::Result<String> {
    let output = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(containerfile.as_bytes())?;
            child.wait_with_output()
        })
        .context("sha256sum")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("sha256sum failed: {stderr}");
    }
    let hash = String::from_utf8(output.stdout).context("sha256sum output not utf-8")?;
    // sha256sum outputs "<hash>  -\n"; the hash always starts at position 0.
    let short = hash.get(..16).context("sha256sum output too short")?;
    Ok(format!("krun-test-{short}"))
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

/// Builds a podman image from `containerfile`, creates a container, and extracts
/// its filesystem directly into `dest` (no intermediate tarball).
///
/// Returns an error if podman is unavailable or the build/export fails.
pub fn prepare_rootfs(containerfile: &str, dest: &Path) -> anyhow::Result<()> {
    if !podman_available() {
        bail!("podman not available");
    }

    let tag = containerfile_tag(containerfile)?;

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

    // Create a container from the image
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

    // Pipe podman export directly into tar extract
    fs::create_dir_all(dest).context("creating rootfs destination directory")?;

    let mut export = Command::new("podman")
        .args(["export", &ctr_id])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("podman export")?;

    let export_stdout = export.stdout.take().unwrap();

    let tar_status = Command::new("tar")
        .args(["-x", "--no-same-owner", "-C"])
        .arg(dest)
        .stdin(export_stdout)
        .status()
        .context("tar extract from podman export")?;

    let export_out = export
        .wait_with_output()
        .context("waiting for podman export")?;

    if !export_out.status.success() {
        bail!("podman export failed");
    }
    if !tar_status.success() {
        bail!("tar extraction failed");
    }

    Ok(())
}

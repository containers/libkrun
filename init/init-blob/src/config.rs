// SPDX-License-Identifier: Apache-2.0
//
//! Builder for the `/.krun_config.json` file consumed by the in-guest init.
//!
//! The JSON schema matches the OCI runtime-spec config.json format that
//! `init/init-binary/src/config.rs` expects:
//!
//! ```json
//! {
//!   "process": {
//!     "args": ["/usr/bin/bash", "--login"],
//!     "env": ["HOME=/root", "TERM=xterm-256color"],
//!     "cwd": "/home/user"
//!   },
//!   "mounts": [{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"}]
//! }
//! ```
//!
//! Callers should not rely on the serialization format — it is an internal
//! detail shared between init-blob and the init binary.
//!
//! # Example (Rust)
//!
//! ```ignore
//! use init_blob::Config;
//!
//! let config = Config::builder()
//!     .args(&["/usr/bin/bash", "--login"])
//!     .env(&["HOME=/root", "TERM=xterm-256color"])
//!     .workdir("/home/user")
//!     .build();
//!
//! for file in config.guest_files() {
//!     // inject file.path, file.data, file.mode, file.one_shot
//! }
//! ```
//!
//! # Example (C via ffier)
//!
//! ```c
//! KrunInitConfig cfg = krun_init_config_builder_build(&b);
//! uint32_t n = krun_init_config_guest_file_count(cfg);
//! for (uint32_t i = 0; i < n; i++) {
//!     KrunInitStr path = krun_init_config_guest_file_path(cfg, i);
//!     KrunInitBytes data = krun_init_config_guest_file_data(cfg, i);
//!     uint32_t mode = krun_init_config_guest_file_mode(cfg, i);
//!     bool one_shot = krun_init_config_guest_file_one_shot(cfg, i);
//!     krun_fs_add_overlay_file(ctx, fs_tag, path.data, data.data, data.len, mode, one_shot);
//! }
//! krun_init_config_destroy(cfg);
//! ```

use std::borrow::Cow;

use crate::FfiBorrow;
use crate::FfiType;
use serde::{Deserialize, Serialize};

/// Error type for init configuration operations.
#[derive(Clone, Debug, thiserror::Error, ffier::FfiError)]
#[non_exhaustive]
pub enum ConfigError {
    /// The JSON string could not be parsed.
    #[error("invalid config JSON: {0}")]
    #[ffier(code = 1)]
    InvalidJson(Box<str>),
}

/// Guest-side path of the init binary (e.g. for `init=` kernel arg).
pub const INIT_PATH: &str = "/init.krun";

/// Kernel cmdline argument to boot with the embedded init.
pub const KERNEL_INIT_ARG: &str = "init=/init.krun";

/// A file that the init process expects to find on the guest root filesystem.
///
/// The caller decides how to materialize these (virtiofs overlay, block
/// device, etc.) — init-blob only describes *what* init needs.
pub struct GuestFile {
    /// Path on the guest root filesystem.
    pub path: &'static str,
    /// File contents.
    pub data: Cow<'static, [u8]>,
    /// Permission bits (e.g. `0o755` for executables).
    pub mode: u32,
    /// If true, the file is only needed during early init and can be
    /// removed after first use.
    pub one_shot: bool,
}

#[ffier::exportable]
impl GuestFile {
    /// Path on the guest root filesystem (e.g. `"/init.krun"`).
    pub fn path(&self) -> &str {
        self.path
    }

    /// File contents.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Permission mode bits (e.g. `0o755`).
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Whether this file is one-shot (removed after first lookup).
    pub fn one_shot(&self) -> bool {
        self.one_shot
    }
}

/// OCI runtime-spec "process" object (serialization helper).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct ProcessConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    args: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    env: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
}

/// A mount specification for the guest init.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub fs_type: String,
    pub source: String,
}

/// Serialization envelope (matches what the init binary parses).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct ConfigJson {
    #[serde(skip_serializing_if = "ProcessConfig::is_empty")]
    process: ProcessConfig,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<Mount>,
}

impl ProcessConfig {
    fn is_empty(&self) -> bool {
        self.args.is_empty() && self.env.is_empty() && self.cwd.is_none()
    }
}

/// Built init configuration. Immutable after construction.
///
/// Holds pre-computed guest files. Methods return borrowed references
/// valid for the lifetime of this value.
pub struct Config {
    files: Vec<GuestFile>,
    kernel_cmdline: String,
}

#[ffier::exportable]
impl Config {
    /// Start building a new init configuration.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Construct from an OCI runtime-spec config.json string.
    ///
    /// The JSON is expected to use the OCI runtime-spec layout:
    /// `{"process": {"args": [...], "env": [...], "cwd": "..."}, "mounts": [...]}`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the JSON is syntactically invalid or contains
    /// unexpected types.
    pub fn from_oci_config_json(json: &str) -> Result<Self, ConfigError> {
        let parsed: ConfigJson = serde_json::from_str(json)
            .map_err(|e| ConfigError::InvalidJson(e.to_string().into()))?;
        Ok(Self::from_config_json(parsed, String::new()))
    }

    /// Returns the kernel cmdline fragments needed by this init config
    /// (e.g. `"init=/init.krun KRUN_DHCP=1"`).
    ///
    /// Pass to [`LoadedKernel::apply_init_config()`] or
    /// [`LoadedKernel::append_cmdline()`].
    pub fn kernel_cmdline(&self) -> &str {
        &self.kernel_cmdline
    }

    /// Returns the guest files that need to be injected into the guest
    /// root filesystem.
    pub fn guest_files(&self) -> &[GuestFile] {
        &self.files
    }
}

impl Config {
    fn from_config_json(config: ConfigJson, extras: String) -> Self {
        let config_json =
            serde_json::to_vec(&config).expect("ConfigJson serialization cannot fail");
        Self {
            files: vec![
                GuestFile {
                    path: INIT_PATH,
                    data: Cow::Borrowed(super::INIT_BINARY),
                    mode: 0o755,
                    one_shot: true,
                },
                GuestFile {
                    path: "/.krun_config.json",
                    data: Cow::Owned(config_json),
                    mode: 0o644,
                    one_shot: true,
                },
            ],
            kernel_cmdline: if extras.is_empty() {
                KERNEL_INIT_ARG.to_string()
            } else {
                format!("{KERNEL_INIT_ARG} {extras}")
            },
        }
    }
}

/// Builder for [`Config`].
#[derive(Clone, Debug, Default)]
pub struct ConfigBuilder {
    inner: ConfigJson,
    rlimits: Vec<String>,
    dhcp: bool,
    block_root: Option<BlockRootConfig>,
}

#[derive(Clone, Debug)]
struct BlockRootConfig {
    device: String,
    fstype: Option<String>,
    options: Option<String>,
}

#[ffier::exportable]
impl ConfigBuilder {
    /// Set the full argv: `args[0]` is the executable, `args[1..]` are arguments.
    pub fn args(mut self, argv: &[&str]) -> Self {
        self.inner.process.args = argv.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set environment variables. Each entry should be `"KEY=value"`.
    pub fn env(mut self, vars: &[&str]) -> Self {
        self.inner.process.env = vars.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set the guest working directory.
    pub fn workdir(mut self, dir: &str) -> Self {
        self.inner.process.cwd = Some(dir.to_string());
        self
    }

    /// Add a mount specification.
    pub fn mount(mut self, destination: &str, fs_type: &str, source: &str) -> Self {
        self.inner.mounts.push(Mount {
            destination: destination.to_string(),
            fs_type: fs_type.to_string(),
            source: source.to_string(),
        });
        self
    }

    /// Set resource limits. Each entry should be `"id=cur:max"` (e.g. `"7=0:0"`).
    pub fn rlimits(mut self, limits: &[&str]) -> Self {
        self.rlimits = limits.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Enable the in-guest DHCP client for network autoconfiguration.
    ///
    /// Passes `KRUN_DHCP=1` on the kernel cmdline so that the init
    /// binary runs udhcpc after boot.
    pub fn dhcp(mut self, enable: bool) -> Self {
        self.dhcp = enable;
        self
    }

    /// Configure the init to pivot from the initial root to a block
    /// device after boot.
    ///
    /// The init process will mount `device` as `fstype` and pivot_root
    /// to it. Passes `KRUN_BLOCK_ROOT_DEVICE=...` (and optionally
    /// `KRUN_BLOCK_ROOT_FSTYPE` / `KRUN_BLOCK_ROOT_OPTIONS`) on the
    /// kernel cmdline.
    pub fn block_root(mut self, device: &str, fstype: Option<&str>, options: Option<&str>) -> Self {
        self.block_root = Some(BlockRootConfig {
            device: device.to_string(),
            fstype: fstype.map(|s| s.to_string()),
            options: options.map(|s| s.to_string()),
        });
        self
    }

    /// Consume the builder, serialize the config, and return the
    /// finished [`Config`].
    pub fn build(mut self) -> Config {
        // Inject rlimits as KRUN_RLIMITS env var.
        if !self.rlimits.is_empty() {
            let value = self.rlimits.join(",");
            self.inner
                .process
                .env
                .retain(|e| !e.starts_with("KRUN_RLIMITS="));
            self.inner.process.env.push(format!("KRUN_RLIMITS={value}"));
        }

        // Build kernel cmdline extras.
        let mut extras = String::new();
        if self.dhcp {
            extras.push_str("KRUN_DHCP=1");
        }
        if let Some(br) = &self.block_root {
            if !extras.is_empty() {
                extras.push(' ');
            }
            extras.push_str(&format!("KRUN_BLOCK_ROOT_DEVICE={}", br.device));
            if let Some(fstype) = &br.fstype {
                extras.push_str(&format!(" KRUN_BLOCK_ROOT_FSTYPE={fstype}"));
            }
            if let Some(options) = &br.options {
                extras.push_str(&format!(" KRUN_BLOCK_ROOT_OPTIONS={options}"));
            }
        }

        Config::from_config_json(self.inner, extras)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config_json(cfg: &Config) -> serde_json::Value {
        let config_file = &cfg.guest_files()[1];
        serde_json::from_slice(&config_file.data).unwrap()
    }

    #[test]
    fn builder_produces_valid_config() {
        let cfg = Config::builder()
            .args(&["/usr/bin/bash", "--login"])
            .env(&["HOME=/root", "TERM=xterm-256color"])
            .workdir("/home/user")
            .mount("/tmp", "tmpfs", "tmpfs")
            .rlimits(&["7=0:0"])
            .build();

        let json = parse_config_json(&cfg);
        assert_eq!(
            json["process"]["args"],
            serde_json::json!(["/usr/bin/bash", "--login"])
        );
        assert_eq!(json["process"]["cwd"], "/home/user");
        assert_eq!(json["mounts"][0]["type"], "tmpfs");

        // rlimits injected as env var
        let env = json["process"]["env"].as_array().unwrap();
        assert!(env.iter().any(|v| v.as_str() == Some("KRUN_RLIMITS=7=0:0")));
    }

    #[test]
    fn from_oci_config_json() {
        let json = r#"{"process":{"args":["/bin/sh"],"cwd":"/"}}"#;
        let cfg = Config::from_oci_config_json(json).unwrap();
        let parsed = parse_config_json(&cfg);
        assert_eq!(parsed["process"]["args"], serde_json::json!(["/bin/sh"]));
    }

    #[test]
    fn guest_files_contains_init_and_config() {
        let cfg = Config::builder().args(&["/bin/sh"]).build();
        let files = cfg.guest_files();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, INIT_PATH);
        assert!(!files[0].data.is_empty());
        assert_eq!(files[1].path, "/.krun_config.json");
    }
}

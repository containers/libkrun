#[cfg(target_os = "freebsd")]
use crate::freebsd::ISO_CONFIG_PATH;
use std::env;
use std::fs;
#[cfg(target_os = "freebsd")]
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

const CONFIG_FILE_PATH: &str = "/.krun_config.json";

// The krun OCI runtime passes a full OCI runtime-spec config.json as the
// config file.  The fields we care about live inside "process".
#[derive(Deserialize, Default)]
struct ProcessConfig {
    args: Option<Vec<String>>,
    env: Option<Vec<String>>,
    cwd: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Default)]
struct Mount {
    #[serde(rename = "destination")]
    destination: Option<String>,
    #[serde(rename = "type")]
    mount_type: Option<String>,
    #[serde(rename = "source")]
    source: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawConfig {
    process: Option<ProcessConfig>,
    // Flat format: "args"/"env"/"cwd" at the top level (used by simple configs and tests).
    // Only consulted when "process" is absent.
    args: Option<Vec<String>>,
    env: Option<Vec<String>>,
    cwd: Option<String>,
    #[cfg(target_os = "linux")]
    mounts: Option<Vec<Mount>>,
}

#[derive(Default)]
pub struct Config {
    pub argv: Option<Vec<String>>,
    pub workdir: Option<String>,
    #[cfg(target_os = "linux")]
    pub tmpfs: Option<String>,
}

pub fn load(#[cfg(target_os = "linux")] is_mount_point: impl Fn(&str) -> bool) -> Config {
    let path = env::var("KRUN_CONFIG").unwrap_or_else(|_| {
        #[cfg(target_os = "freebsd")]
        if Path::new(ISO_CONFIG_PATH).exists() {
            return ISO_CONFIG_PATH.to_string();
        }
        CONFIG_FILE_PATH.to_string()
    });

    let Ok(raw) = parse_file(&path) else {
        return Config::default();
    };

    let process = raw.process.unwrap_or(ProcessConfig {
        args: raw.args,
        env: raw.env,
        cwd: raw.cwd,
    });

    // Apply environment variables from the process config.
    for entry in process.env.unwrap_or_default() {
        let Some((key, val)) = entry.split_once('=') else {
            continue;
        };
        let overwrite = matches!(key, "HOME" | "TERM");
        if env::var(key).is_err() || overwrite {
            // SAFETY: single-threaded at this point.
            unsafe { env::set_var(key, val) };
        }
    }

    let argv = process.args.filter(|v| !v.is_empty());
    let workdir = process.cwd;

    // Find the first tmpfs mount whose destination is not already mounted.
    #[cfg(target_os = "linux")]
    let tmpfs = raw.mounts.unwrap_or_default().into_iter().find_map(|m| {
        let dest = m.destination?;
        let ty = m.mount_type.as_deref().unwrap_or("");
        let src = m.source.as_deref().unwrap_or("");
        if ty == "tmpfs" && src == "tmpfs" && !is_mount_point(&dest) {
            Some(dest)
        } else {
            None
        }
    });

    Config {
        argv,
        workdir,
        #[cfg(target_os = "linux")]
        tmpfs,
    }
}

fn parse_file(path: &str) -> Result<RawConfig> {
    let data = fs::read(path).with_context(|| format!("read {path}"))?;
    serde_json::from_slice(&data).with_context(|| format!("parse {path}"))
}

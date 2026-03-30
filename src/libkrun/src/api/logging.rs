use std::fs::File;
use std::os::fd::{FromRawFd, RawFd};

use env_logger::{Env, Target};

use super::error::Error;

#[ffier::exportable]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

#[ffier::exportable]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStyle {
    Auto = 0,
    Always = 1,
    Never = 2,
}

#[ffier::exportable]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogTarget {
    /// Default target (stderr).
    Default = 0,
    Stdout = 1,
    Stderr = 2,
}

#[ffier::exportable]
pub fn init_log(target: LogTarget, level: LogLevel, style: LogStyle) -> Result<(), Error> {
    let target = match target {
        LogTarget::Default => Target::default(),
        LogTarget::Stdout => Target::Stdout,
        LogTarget::Stderr => Target::Stderr,
    };

    let filter = match level {
        LogLevel::Off => "off",
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    };

    let write_style = match style {
        LogStyle::Auto => "auto",
        LogStyle::Always => "always",
        LogStyle::Never => "never",
    };

    let mut builder = env_logger::Builder::from_env(
        Env::new()
            .default_filter_or(filter)
            .default_write_style_or(write_style),
    );
    builder.format_timestamp_micros().target(target).init();

    Ok(())
}

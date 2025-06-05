// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// Errors associated with actions on `RootfsConfig`.
#[derive(Debug)]
pub enum RootfsConfigError {
    /// Invalid device specification.
    InvalidDevice(String),
    /// Invalid filesystem type.
    InvalidFsType(String),
    /// Invalid mount flags.
    InvalidMountFlags(String),
}

impl fmt::Display for RootfsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::RootfsConfigError::*;
        match *self {
            InvalidDevice(ref e) => write!(f, "Invalid device specification: {}", e),
            InvalidFsType(ref e) => write!(f, "Invalid filesystem type: {}", e),
            InvalidMountFlags(ref e) => write!(f, "Invalid mount flags: {}", e),
        }
    }
}

type RootfsResult<T> = std::result::Result<T, RootfsConfigError>;

/// Strongly typed data structure used to configure the root filesystem
/// kernel arguments for the microvm.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RootfsConfig {
    /// The device on which the root filesystem should be found.
    /// Defaults to "/dev/vda1" if not specified.
    pub device: Option<String>,
    /// The type of the filesystem on the device.
    /// Defaults to "virtiofs" if not specified.
    pub fs_type: Option<String>,
    /// Additional mount flags to be used when mounting the root filesystem.
    pub mount_flags: Option<String>,
    /// Whether to mount the root filesystem read-only.
    /// If false, mount read-write.
    pub read_only: bool,
}

impl RootfsConfig {
    /// Create a new RootfsConfig with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the device for the root filesystem
    pub fn with_device<S: Into<String>>(mut self, device: S) -> RootfsResult<Self> {
        let device_str = device.into();
        if device_str.is_empty() {
            return Err(RootfsConfigError::InvalidDevice(
                "Device cannot be empty".to_string(),
            ));
        }
        self.device = Some(device_str);
        Ok(self)
    }

    /// Set the filesystem type
    pub fn with_fs_type<S: Into<String>>(mut self, fs_type: S) -> RootfsResult<Self> {
        let fs_type_str = fs_type.into();
        if fs_type_str.is_empty() {
            return Err(RootfsConfigError::InvalidFsType(
                "Filesystem type cannot be empty".to_string(),
            ));
        }
        self.fs_type = Some(fs_type_str);
        Ok(self)
    }

    /// Set the mount flags
    pub fn with_mount_flags<S: Into<String>>(mut self, mount_flags: S) -> RootfsResult<Self> {
        self.mount_flags = Some(mount_flags.into());
        Ok(self)
    }

    /// Set whether the filesystem should be mounted read-only
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Get the device, with default fallback
    pub fn get_device(&self) -> &str {
        self.device.as_deref().unwrap_or("/dev/vda1")
    }

    /// Get the filesystem type, with default fallback
    pub fn get_fs_type(&self) -> &str {
        self.fs_type.as_deref().unwrap_or("virtiofs")
    }

    /// Get the mount flags, if any
    pub fn get_mount_flags(&self) -> Option<&str> {
        self.mount_flags.as_deref()
    }

    /// Generate kernel command line arguments from this config
    pub fn to_kernel_args(&self) -> String {
        let mut args = Vec::new();

        // Add root device
        args.push(format!("root={}", self.get_device()));

        // Add filesystem type
        args.push(format!("rootfstype={}", self.get_fs_type()));

        // Add mount flags if specified
        if let Some(flags) = self.get_mount_flags() {
            if !flags.is_empty() {
                args.push(format!("rootflags={}", flags));
            }
        }

        // Add read-only or read-write
        if self.read_only {
            args.push("ro".to_string());
        } else {
            args.push("rw".to_string());
        }

        args.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RootfsConfig::new();
        assert_eq!(config.get_device(), "/dev/vda1");
        assert_eq!(config.get_fs_type(), "virtiofs");
        assert_eq!(config.get_mount_flags(), None);
        assert!(!config.read_only);
    }

    #[test]
    fn test_custom_config() {
        let config = RootfsConfig::new()
            .with_device("/dev/vdb1")
            .unwrap()
            .with_fs_type("ext4")
            .unwrap()
            .with_mount_flags("noatime,discard")
            .unwrap()
            .with_read_only(true);

        assert_eq!(config.get_device(), "/dev/vdb1");
        assert_eq!(config.get_fs_type(), "ext4");
        assert_eq!(config.get_mount_flags(), Some("noatime,discard"));
        assert!(config.read_only);
    }

    #[test]
    fn test_to_kernel_args_default() {
        let config = RootfsConfig::new();
        let args = config.to_kernel_args();
        assert_eq!(args, "root=/dev/vda1 rootfstype=virtiofs rw");
    }

    #[test]
    fn test_to_kernel_args_custom() {
        let config = RootfsConfig::new()
            .with_device("/dev/vdb1")
            .unwrap()
            .with_fs_type("ext4")
            .unwrap()
            .with_mount_flags("noatime,discard")
            .unwrap()
            .with_read_only(true);

        let args = config.to_kernel_args();
        assert_eq!(
            args,
            "root=/dev/vdb1 rootfstype=ext4 rootflags=noatime,discard ro"
        );
    }

    #[test]
    fn test_invalid_device() {
        let result = RootfsConfig::new().with_device("");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_fs_type() {
        let result = RootfsConfig::new().with_fs_type("");
        assert!(result.is_err());
    }
}

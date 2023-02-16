use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use devices::virtio::{Fs, FsError};

const ROSETTA_DIR: &str = "/Library/Apple/usr/libexec/oah/RosettaLinux";

#[derive(Debug)]
pub enum FsConfigError {
    /// Failed to create the fs device.
    CreateFsDevice(FsError),
}

impl fmt::Display for FsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::FsConfigError::*;
        match *self {
            CreateFsDevice(ref e) => write!(f, "Cannot create vsock device: {e:?}"),
        }
    }
}

type Result<T> = std::result::Result<T, FsConfigError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsDeviceConfig {
    pub fs_id: String,
    pub shared_dir: String,
    pub mapped_volumes: Option<Vec<(PathBuf, PathBuf)>>,
}

#[derive(Default)]
pub struct FsBuilder {
    pub list: VecDeque<Arc<Mutex<Fs>>>,
}

impl FsBuilder {
    pub fn new() -> Self {
        Self {
            list: VecDeque::<Arc<Mutex<Fs>>>::new(),
        }
    }

    pub fn insert(&mut self, config: FsDeviceConfig) -> Result<()> {
        let fs_dev = Arc::new(Mutex::new(Self::create_fs(config)?));
        self.list.push_back(fs_dev);
        Ok(())
    }

    pub fn create_fs(config: FsDeviceConfig) -> Result<Fs> {
        let mapped_volumes = if cfg!(target_os = "macos") && std::fs::metadata(ROSETTA_DIR).is_ok()
        {
            if let Some(config_mapped_volumes) = config.mapped_volumes {
                let mut mapped_volumes = config_mapped_volumes.to_vec();
                mapped_volumes.push((
                    Path::new(ROSETTA_DIR).to_path_buf(),
                    Path::new("/.rosetta").to_path_buf(),
                ));
                Some(mapped_volumes)
            } else {
                Some(vec![(
                    Path::new(ROSETTA_DIR).to_path_buf(),
                    Path::new("/.rosetta").to_path_buf(),
                )])
            }
        } else {
            config.mapped_volumes
        };
        devices::virtio::Fs::new(config.fs_id, config.shared_dir, mapped_volumes)
            .map_err(FsConfigError::CreateFsDevice)
    }
}

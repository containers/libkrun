use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use devices::virtio::{Fs, FsError};

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
        devices::virtio::Fs::new(config.fs_id, config.shared_dir)
            .map_err(FsConfigError::CreateFsDevice)
    }
}

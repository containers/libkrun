use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use devices::virtio::{Console, ConsoleError};

#[derive(Debug)]
pub enum ConsoleConfigError {
    /// Failed to create the console device.
    CreateConsoleDevice(ConsoleError),
}

impl fmt::Display for ConsoleConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ConsoleConfigError::*;
        match *self {
            CreateConsoleDevice(ref e) => write!(f, "Cannot create console device: {:?}", e),
        }
    }
}

type Result<T> = std::result::Result<T, ConsoleConfigError>;

#[derive(Clone, Debug, PartialEq)]
pub struct ConsoleDeviceConfig {
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
        Ok(devices::virtio::Fs::new(config.fs_id, config.shared_dir)
            .map_err(FsConfigError::CreateFsDevice)?)
    }
}

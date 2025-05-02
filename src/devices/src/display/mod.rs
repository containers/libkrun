mod noop;

pub use noop::DisplayBackendNoop;
use std::io;

#[cfg(feature = "gtk_display")]
mod gtk;
#[cfg(feature = "gtk_display")]
pub use gtk::DisplayBackendGtk;

use crate::virtio::GpuResourceFormat;
use thiserror::Error;
use virtio_bindings::virtio_gpu::VIRTIO_GPU_MAX_SCANOUTS;

#[derive(Clone, Debug)]
pub struct DisplayInfo {
    pub width: u32,
    pub height: u32,
}

pub const MAX_DISPLAYS: usize = VIRTIO_GPU_MAX_SCANOUTS as usize;
pub type DisplayInfoList = [Option<DisplayInfo>; MAX_DISPLAYS];

impl DisplayInfo {
    pub fn new(width: u32, height: u32) -> Self {
        DisplayInfo { width, height }
    }
}

#[derive(Error, Debug)]
pub enum DisplayBackendError {
    #[error("Invalid scanout id")]
    InvalidScanoutId,
    #[error("Invalid parameter")]
    InvalidParameter,
    #[error("Internal IO error: {0}")]
    InternalIOError(#[from] io::Error),
}

pub trait DisplayBackend: Send {
    fn displays(&self) -> &DisplayInfoList;

    fn num_displays(&self) -> u32 {
        self.displays().len() as u32
    }

    fn configure_scanout(
        &self,
        scanout_id: u32,
        width: u32,
        height: u32,
        format: GpuResourceFormat,
    ) -> Result<(), DisplayBackendError>;

    fn disable_scanout(&self, scanout_id: u32) -> Result<(), DisplayBackendError>;

    fn update_scanout(
        &self,
        scanout_id: u32,
        data: Vec<u8>,
        stride: u32,
    ) -> Result<(), DisplayBackendError>;
}

pub fn check_scanout_id(
    backend: &impl DisplayBackend,
    scanout_id: u32,
) -> Result<(), DisplayBackendError> {
    let displays = backend.displays();

    if displays
        .get(scanout_id as usize)
        .is_some_and(|d| d.is_some())
    {
        Ok(())
    } else {
        Err(DisplayBackendError::InvalidScanoutId)
    }
}

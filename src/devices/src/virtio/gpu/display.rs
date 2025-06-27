use krun_display::{DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendNew};
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

pub struct NoopDisplayBackend;

impl DisplayBackendNew<()> for NoopDisplayBackend {
    fn new(_userdata: Option<&()>) -> Self {
        Self
    }
}

impl DisplayBackendBasicFramebuffer for NoopDisplayBackend {
    fn configure_scanout(
        &mut self,
        _scanout_id: u32,
        _display_width: u32,
        _display_height: u32,
        _width: u32,
        _height: u32,
        _format: u32,
    ) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn disable_scanout(&mut self, _scanout_id: u32) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn alloc_frame(&mut self, _scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn present_frame(
        &mut self,
        _scanout_id: u32,
        _frame_id: u32,
    ) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }
}

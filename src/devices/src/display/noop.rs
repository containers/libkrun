use crate::display::{DisplayBackend, DisplayBackendError, DisplayInfoList, MAX_DISPLAYS};
use crate::virtio::GpuResourceFormat;

pub struct DisplayBackendNoop;

impl DisplayBackend for DisplayBackendNoop {
    fn displays(&self) -> &DisplayInfoList {
        static NO_DISPLAYS: DisplayInfoList = [const { None }; MAX_DISPLAYS];
        &NO_DISPLAYS
    }

    fn configure_scanout(
        &self,
        _scanout_id: u32,
        _width: u32,
        _height: u32,
        _format: GpuResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn disable_scanout(&self, _scanout_id: u32) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn update_scanout(
        &self,
        _scanout_id: u32,
        _data: Vec<u8>,
        _stride: u32,
    ) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }
}

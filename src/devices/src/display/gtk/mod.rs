mod worker;

use crate::display::gtk::worker::gtk_display_main_loop;
use crate::display::{check_scanout_id, DisplayBackend, DisplayBackendError, DisplayInfoList};
use crate::virtio::GpuResourceFormat;
use gtk4::gdk;
use std::thread;
use utils::pollable_channel::{pollable_channel, PollableChannelSender};

enum DisplayEvent {
    ConfigureScanout {
        scanout_id: u32,
        width: i32,
        height: i32,
        format: gdk::MemoryFormat,
    },
    DisableScanout {
        scanout_id: u32,
    },
    UpdateScanout {
        scanout_id: u32,
        data: Vec<u8>,
        /// stride/pitch of row specified in bytes
        stride: u32,
    },
}

pub struct DisplayBackendGtk {
    tx: PollableChannelSender<DisplayEvent>,
    displays: DisplayInfoList,
}

fn resource_format_into_gdk(format: GpuResourceFormat) -> gdk::MemoryFormat {
    match format {
        GpuResourceFormat::BGRA => gdk::MemoryFormat::B8g8r8a8,
        GpuResourceFormat::BGRX => gdk::MemoryFormat::B8g8r8x8,
        GpuResourceFormat::ARGB => gdk::MemoryFormat::A8r8g8b8,
        GpuResourceFormat::XRGB => gdk::MemoryFormat::X8r8g8b8,
        GpuResourceFormat::RGBA => gdk::MemoryFormat::R8g8b8a8,
        GpuResourceFormat::XBGR => gdk::MemoryFormat::X8b8g8r8,
        GpuResourceFormat::ABGR => gdk::MemoryFormat::A8b8g8r8,
        GpuResourceFormat::RGBX => gdk::MemoryFormat::R8g8b8x8,
    }
}

impl DisplayBackendGtk {
    pub fn new(displays: DisplayInfoList) -> DisplayBackendGtk {
        let (tx, rx) = pollable_channel().unwrap();
        let displays_clone = displays.clone();
        thread::Builder::new()
            .name("gtk display".to_string())
            .spawn(move || {
                gtk_display_main_loop(rx, displays_clone);
            })
            .unwrap();

        Self { displays, tx }
    }
}

impl DisplayBackend for DisplayBackendGtk {
    fn displays(&self) -> &DisplayInfoList {
        &self.displays
    }

    fn configure_scanout(
        &self,
        scanout_id: u32,
        width: u32,
        height: u32,
        format: GpuResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        check_scanout_id(self, scanout_id)?;
        let Ok(width) = width.try_into() else {
            warn!("Display width out of range");
            return Err(DisplayBackendError::InvalidParameter);
        };

        let Ok(height) = height.try_into() else {
            warn!("Display width out of range");
            return Err(DisplayBackendError::InvalidParameter);
        };

        let format = resource_format_into_gdk(format);

        self.tx.send(DisplayEvent::ConfigureScanout {
            scanout_id,
            width,
            height,
            format,
        })?;
        Ok(())
    }

    fn disable_scanout(&self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        check_scanout_id(self, scanout_id)?;
        self.tx.send(DisplayEvent::DisableScanout { scanout_id })?;
        Ok(())
    }

    fn update_scanout(
        &self,
        scanout_id: u32,
        data: Vec<u8>,
        stride: u32,
    ) -> Result<(), DisplayBackendError> {
        check_scanout_id(self, scanout_id)?;

        self.tx.send(DisplayEvent::UpdateScanout {
            scanout_id,
            data,
            stride,
        })?;
        Ok(())
    }
}

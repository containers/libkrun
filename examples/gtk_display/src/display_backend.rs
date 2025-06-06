use crate::event::DisplayEvent;
use gtk4::gdk;
use krun_display::{DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendNew};
use log::error;
use utils::pollable_channel::PollableChannelSender;

const MAX_SCANOUTS: usize = 16;
const BYTES_PER_PIXEL: usize = 4;

pub struct GtkDisplayBackend {
    channel: PollableChannelSender<DisplayEvent>,
    scanout_buffers: [Option<Vec<u8>>; MAX_SCANOUTS],
}

impl DisplayBackendNew<PollableChannelSender<DisplayEvent>> for GtkDisplayBackend {
    fn new(channel: Option<&PollableChannelSender<DisplayEvent>>) -> Self {
        let channel = channel.unwrap().clone();

        Self {
            channel,
            scanout_buffers: Default::default(),
        }
    }
}

fn resource_format_into_gdk(format: u32) -> Result<gdk::MemoryFormat, DisplayBackendError> {
    Ok(match format {
        krun_sys::KRUN_PIXEL_FORMAT_B8G8R8A8_UNORM => gdk::MemoryFormat::B8g8r8a8,
        krun_sys::KRUN_PIXEL_FORMAT_B8G8R8X8_UNORM => gdk::MemoryFormat::B8g8r8x8,
        krun_sys::KRUN_PIXEL_FORMAT_A8R8G8B8_UNORM => gdk::MemoryFormat::A8r8g8b8,
        krun_sys::KRUN_PIXEL_FORMAT_X8R8G8B8_UNORM => gdk::MemoryFormat::X8r8g8b8,
        krun_sys::KRUN_PIXEL_FORMAT_R8G8B8A8_UNORM => gdk::MemoryFormat::R8g8b8a8,
        krun_sys::KRUN_PIXEL_FORMAT_X8B8G8R8_UNORM => gdk::MemoryFormat::X8b8g8r8,
        krun_sys::KRUN_PIXEL_FORMAT_A8B8G8R8_UNORM => gdk::MemoryFormat::A8b8g8r8,
        krun_sys::KRUN_PIXEL_FORMAT_R8G8B8X8_UNORM => gdk::MemoryFormat::R8g8b8x8,
        format => {
            error!("Unknown pixel format: {format}");
            return Err(DisplayBackendError::InvalidParam);
        }
    })
}

impl DisplayBackendBasicFramebuffer for GtkDisplayBackend {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: u32,
    ) -> Result<(), DisplayBackendError> {
        if let Some(ref mut scanout_buffer) = self.scanout_buffers[scanout_id as usize] {
            scanout_buffer.resize(width as usize * height as usize * BYTES_PER_PIXEL, 0)
        } else {
            self.scanout_buffers[scanout_id as usize] =
                Some(vec![0; width as usize * height as usize * BYTES_PER_PIXEL]);
        }

        self.channel
            .send(DisplayEvent::ConfigureScanout {
                scanout_id,
                display_width,
                display_height,
                width,
                height,
                format: resource_format_into_gdk(format)?,
            })
            .unwrap();
        Ok(())
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        self.scanout_buffers[scanout_id as usize] = None;
        self.channel
            .send(DisplayEvent::DisableScanout { scanout_id })
            .unwrap();
        Ok(())
    }

    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        let Some(scanout_buffer) = &mut self.scanout_buffers[scanout_id as usize] else {
            return Err(DisplayBackendError::InvalidScanoutId);
        };

        Ok((1, &mut scanout_buffer[..]))
    }

    fn present_frame(&mut self, scanout_id: u32, frame_id: u32) -> Result<(), DisplayBackendError> {
        assert_eq!(frame_id, 1);

        let Some(scanout_buffer) = &mut self.scanout_buffers[scanout_id as usize] else {
            return Err(DisplayBackendError::InvalidScanoutId);
        };

        self.channel
            .send(DisplayEvent::UpdateScanout {
                scanout_id,
                data: scanout_buffer.clone(),
            })
            .unwrap();
        Ok(())
    }
}

use gtk4::gdk;

#[derive(Debug, Clone)]
pub enum DisplayEvent {
    ConfigureScanout {
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: gdk::MemoryFormat,
    },
    DisableScanout {
        scanout_id: u32,
    },
    UpdateScanout {
        scanout_id: u32,
        data: Vec<u8>,
    },
}

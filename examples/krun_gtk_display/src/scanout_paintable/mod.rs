mod imp;

#[cfg(target_os = "linux")]
use crate::display_worker::SharedDmabuf;
#[cfg(target_os = "linux")]
use crate::scanout_paintable::imp::DmabufUpdate;
use gtk::{
    cairo::{RectangleInt, Region},
    gdk::{self, MemoryFormat, MemoryTextureBuilder},
    glib,
    glib::Bytes,
    prelude::*,
    subclass::prelude::*,
};
use krun_display::{Rect, ResourceFormat};

glib::wrapper! {
    pub struct ScanoutPaintable(ObjectSubclass<imp::ScanoutPaintable>) @implements gdk::Paintable;
}

impl ScanoutPaintable {
    pub fn new(default_width: i32, default_height: i32) -> Self {
        glib::Object::builder()
            .property("width", default_width)
            .property("height", default_height)
            .build()
    }

    pub fn update(
        &self,
        buffer: Bytes,
        width: i32,
        height: i32,
        format: MemoryFormat,
        rect: Option<Rect>,
    ) {
        assert_eq!(buffer.len(), width as usize * height as usize * 4);
        let imp = self.imp();
        let builder = MemoryTextureBuilder::new()
            .set_width(width)
            .set_height(height)
            .set_format(format)
            .set_stride(width as usize * ResourceFormat::BYTES_PER_PIXEL)
            .set_bytes(Some(&buffer));

        let builder = if let Some(rect) = rect {
            builder
                .set_update_region(Some(&Region::create_rectangle(&RectangleInt::new(
                    rect.x as i32,
                    rect.y as i32,
                    rect.width as i32,
                    rect.height as i32,
                ))))
                .set_update_texture(imp.texture.borrow().as_ref())
        } else {
            builder
        };

        imp.texture.replace(Some(builder.build()));

        self.invalidate_contents();
        if self.height() != height || self.width() != width {
            self.set_width(width);
            self.set_height(height);
            self.invalidate_size();
        }
    }

    #[cfg(target_os = "linux")]
    pub fn configure_dmabuf(
        &self,
        dmabuf: SharedDmabuf,
        src_rect: Option<Rect>,
        damage_rect: Option<Rect>,
    ) {
        let imp = self.imp();

        let damage_area = if imp.dmabuf_update.borrow().is_some() {
            // We don't currently handle multiple damage area changes
            None
        } else {
            damage_rect
        };

        imp.dmabuf_update.replace(Some(DmabufUpdate {
            dmabuf: dmabuf.clone(),
            damage_area,
        }));

        self.invalidate_contents();
        let (width, height) = if let Some(src_rect) = src_rect {
            (src_rect.width, src_rect.height)
        } else {
            (dmabuf.width, dmabuf.height)
        };
        if self.width() != width as i32 || self.height() != height as i32 {
            self.set_width(width as i32);
            self.set_height(height as i32);
            self.invalidate_size();
        }
    }
}

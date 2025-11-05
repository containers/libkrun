#[cfg(target_os = "linux")]
use crate::display_worker::SharedDmabuf;
use gtk::cairo::{RectangleInt as CairoRect, Region};
#[cfg(target_os = "linux")]
use gtk::gdk::DmabufTextureBuilder;
use gtk::{
    gdk,
    gdk::{Paintable, PaintableFlags, RGBA, Snapshot, Texture},
    glib,
    graphene::Rect as GrapheneRect,
    prelude::*,
    subclass::prelude::*,
};
use krun_display::{Rect as KrunRect, Rect};
use log::debug;
use std::cell::{Cell, RefCell};

#[cfg(target_os = "linux")]
pub struct DmabufUpdate {
    pub dmabuf: SharedDmabuf,
    pub damage_area: Option<Rect>,
}

#[derive(glib::Properties)]
#[properties(wrapper_type = super::ScanoutPaintable)]
#[derive(Default)]
pub struct ScanoutPaintable {
    #[property(get, set)]
    pub width: Cell<i32>,
    #[property(get, set)]
    pub height: Cell<i32>,
    // Store the texture that this paintable will draw.
    pub texture: RefCell<Option<Texture>>,
    pub src_rect: RefCell<Option<KrunRect>>,
    #[cfg(target_os = "linux")]
    pub dmabuf_update: RefCell<Option<DmabufUpdate>>,
}

#[glib::object_subclass]
impl ObjectSubclass for ScanoutPaintable {
    const NAME: &'static str = "ScanoutPaintable";
    type Type = super::ScanoutPaintable;
    type Interfaces = (Paintable,);
}

#[glib::derived_properties]
impl ObjectImpl for ScanoutPaintable {
    fn dispose(&self) {
        debug!("ScanoutPaintable::dispose");
    }
}

#[cfg(target_os = "linux")]
fn build_dmabuf_texture(update: DmabufUpdate, old_texture: Option<&Texture>) -> Option<Texture> {
    let dmabuf = update.dmabuf;
    let damage_area = update.damage_area;

    let n_planes = dmabuf.n_planes;
    assert_eq!(n_planes, 1);
    let mut builder = DmabufTextureBuilder::new()
        .set_display(gdk::Display::default().as_ref().unwrap())
        .set_width(dmabuf.width)
        .set_height(dmabuf.height)
        .set_fourcc(dmabuf.fourcc)
        .set_modifier(dmabuf.modifier)
        .set_n_planes(n_planes);

    // Configure damage area on the texture if provided
    if let Some(damage) = damage_area {
        log::trace!(
            "Building texture with damage area: x={}, y={}, width={}, height={}",
            damage.x,
            damage.y,
            damage.width,
            damage.height
        );

        // Configure damage area on the texture builder
        if let Some(old_tex) = old_texture {
            // Create a cairo region from the damage rectangle
            let rect = CairoRect::new(
                damage.x as i32,
                damage.y as i32,
                damage.width as i32,
                damage.height as i32,
            );
            let region = Region::create_rectangle(&rect);

            builder = builder
                .set_update_texture(Some(old_tex))
                .set_update_region(Some(&region));
        }
    }

    for i in 0..n_planes as usize {
        let stride = dmabuf.strides[i];
        let offset = dmabuf.offsets[i];
        let fd = dmabuf.dmabuf_fds[i];

        builder = builder
            .set_stride(i as u32, stride)
            .set_offset(i as u32, offset);
        // SAFETY: Safe, the lifetime of the fd (on the display side) is managed by reference
        // counting.
        unsafe {
            builder = builder.set_fd(i as u32, fd);
        }
    }

    match unsafe {
        let dmabuf = dmabuf.clone();
        builder.build_with_release_func(move || {
            // This only decrements ref-count, the dmabuf may be shared
            drop(dmabuf);
        })
    } {
        Ok(texture) => {
            let texture_upcast: Texture = texture.upcast();
            Some(texture_upcast)
        }
        Err(e) => {
            log::error!(
                "Failed to build dmabuf texture: {e} (n_planes={}, fds={:?}, fourcc=0x{:08x}, modifier=0x{:016x})",
                dmabuf.n_planes,
                &dmabuf.dmabuf_fds[..dmabuf.n_planes as usize],
                dmabuf.fourcc,
                dmabuf.modifier
            );
            None
        }
    }
}

impl PaintableImpl for ScanoutPaintable {
    fn snapshot(&self, snapshot: &Snapshot, width: f64, height: f64) {
        snapshot.append_color(
            &RGBA::BLACK,
            &GrapheneRect::new(0.0, 0.0, width as f32, height as f32),
        );

        #[cfg(target_os = "linux")]
        if let Some(update) = self.dmabuf_update.borrow_mut().take() {
            let new_texture = build_dmabuf_texture(update, self.texture.borrow().as_ref());
            if let Some(new_texture) = new_texture {
                self.texture.replace(Some(new_texture));
            }
        }

        if let Some(texture) = self.texture.borrow().as_ref() {
            snapshot.append_texture(
                texture,
                &GrapheneRect::new(0.0, 0.0, width as f32, height as f32),
            );
        }
    }

    fn flags(&self) -> PaintableFlags {
        PaintableFlags::empty()
    }

    fn intrinsic_aspect_ratio(&self) -> f64 {
        self.width.get() as f64 / self.height.get() as f64
    }

    fn intrinsic_width(&self) -> i32 {
        self.width.get()
    }

    fn intrinsic_height(&self) -> i32 {
        self.height.get()
    }
}

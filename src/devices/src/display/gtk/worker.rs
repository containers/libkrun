use std::os::fd::AsRawFd;

use crate::display::gtk::DisplayEvent;
use crate::display::{DisplayInfo, DisplayInfoList, MAX_DISPLAYS};
use utils::pollable_channel::PollableChannelReciever;

use gtk4::{
    gdk,
    gio::{ActionEntry, Cancellable, SimpleActionGroup},
    glib::{self, source, Bytes, ControlFlow, IOCondition},
    prelude::*,
    AlertDialog, Align, Button, EventControllerMotion, HeaderBar, Overlay, Picture,
    Revealer, RevealerTransitionType, Window,
};

struct Scanout {
    window: Window,
    width: i32,
    height: i32,
    format: gdk::MemoryFormat,
    picture: Picture,
}

impl Scanout {
    fn new(
        title: String,
        display_info: DisplayInfo,
        width: i32,
        height: i32,
        format: gdk::MemoryFormat,
    ) -> Self {
        let header_bar = HeaderBar::new();
        let window = Window::builder()
            .title(title)
            // remove the close button, since it is unclear what it should do
            .deletable(false)
            // Enforce a minimum window size:
            .height_request(64)
            .titlebar(&header_bar)
            .build();

        let actions = SimpleActionGroup::new();
        actions.add_action_entries([
            ActionEntry::builder("kill")
                .activate(glib::clone!(
                    #[weak]
                    window,
                    move |_, _, _| {
                        let dialog = AlertDialog::builder()
                            .buttons(["Kill VM", "Cancel"].as_ref())
                            .default_button(0)
                            .cancel_button(1)
                            .modal(true)
                            .message("Do you want to kill the VM?")
                            .detail("WARNING: This may lead to loss of data or corruption of the VM image.")
                            .build();
                        dialog.choose(Some(&window), None::<&Cancellable>, |b| {
                            if b.is_ok_and(|b| b == 0) {
                                // SAFETY: Safe because we are terminating the process anyway.
                                // We also use _exit during normal VM exit, so we don't clean up
                                // ever anyway.
                                unsafe { libc::_exit(125) };
                            }
                        });
                    }
                ))
                .build(),
            ActionEntry::builder("fullscreen")
                .activate(glib::clone!(
                    #[weak]
                    window,
                    move |_, _, _| {
                        window.fullscreen();
                    }
                ))
                .build(),
            ActionEntry::builder("unfullscreen")
                .activate(glib::clone!(
                    #[weak]
                    window,
                    move |_, _, _| {
                        window.unfullscreen();
                    }
                ))
                .build(),
        ]);
        window.insert_action_group("scanout", Some(&actions));

        let fullscreen_btn = Button::builder()
            .icon_name("view-fullscreen")
            .tooltip_text("Enter fullscreen mode")
            .action_name("scanout.fullscreen")
            .build();

        let picture = Picture::builder()
            // Set picture dimension to the requested display size,
            // this will make the created window have the appropriate size
            .width_request(display_info.width as i32)
            .height_request(display_info.height as i32)
            .build();

        window.set_titlebar(Some(&header_bar));
        header_bar.pack_start(&build_kill_vm_btn());
        header_bar.pack_end(&fullscreen_btn);

        let overlay = build_overlay(&window);
        overlay.set_child(Some(&picture));
        window.set_child(Some(&overlay));
        window.set_visible(true);

        // Unset the width/height after the window is created to allow resizing the window to
        // be smaller
        picture.set_size_request(-1, -1);

        Self {
            window,
            width,
            height,
            format,
            picture,
        }
    }

    fn update_params(&mut self, width: i32, height: i32, format: gdk::MemoryFormat) {
        self.width = width;
        self.height = height;
        self.format = format;
    }

    fn update(&mut self, data: Vec<u8>, stride: u32) {
        let texture = gdk::MemoryTexture::new(
            self.width,
            self.height,
            self.format,
            &Bytes::from_owned(data),
            stride as usize,
        );
        self.picture.set_paintable(Some(&texture));
    }
}

impl Drop for Scanout {
    fn drop(&mut self) {
        self.window.destroy();
    }
}

fn build_kill_vm_btn() -> Button {
    let kill_vm_btn = Button::builder()
        .label("Kill VM")
        .action_name("scanout.kill")
        .build();
    kill_vm_btn.add_css_class("destructive-action");
    kill_vm_btn
}

fn build_overlay(window: &Window) -> Overlay {
    let overlay_bar = HeaderBar::builder()
        .valign(Align::Start)
        .hexpand_set(false)
        .hexpand(false)
        .opacity(0.8)
        .build();

    let overlay = Overlay::new();
    let revealer = Revealer::builder()
        .transition_type(RevealerTransitionType::SwingDown)
        .transition_duration(300)
        .reveal_child(false)
        .build();
    revealer.set_child(Some(&overlay_bar));
    overlay.add_overlay(&revealer);

    let overlay_unfullscreen_btn = Button::builder()
        .tooltip_text("Exit fullscreen mode")
        .icon_name("view-restore")
        .action_name("window.unfullscreen")
        .build();

    let bar_controller = EventControllerMotion::new();
    bar_controller.connect_leave(glib::clone!(
        #[weak]
        revealer,
        move |_| {
            revealer.set_reveal_child(false);
        }
    ));
    overlay_bar.add_controller(bar_controller);

    let overlay_controller = EventControllerMotion::new();
    overlay_controller.connect_motion(glib::clone!(
        #[weak]
        revealer,
        #[weak]
        window,
        move |_motion, _x, y| {
            if window.is_fullscreen() && y < 1.0 {
                revealer.set_reveal_child(true);
            }
        }
    ));
    overlay.add_controller(overlay_controller);

    overlay_bar.pack_start(&build_kill_vm_btn());
    overlay_bar.pack_end(&overlay_unfullscreen_btn);
    overlay_bar.set_show_title_buttons(false);

    overlay
}

pub fn gtk_display_main_loop(rx: PollableChannelReciever<DisplayEvent>, displays: DisplayInfoList) {
    gtk4::init().expect("Failed to initialize GTK");
    let main_loop = glib::MainLoop::new(None, false);

    let mut scanouts: [Option<Scanout>; MAX_DISPLAYS] = [const { None }; MAX_DISPLAYS];
    let program_name = {
        let args = std::env::args();
        args.into_iter()
            .next()
            .map(|name| format!("{name} (libkrun)"))
            .unwrap_or_else(|| "libkrun".to_string())
    };

    source::unix_fd_add_local(rx.as_raw_fd(), IOCondition::IN, move |_, _| {
        let Some(msg) = rx.try_recv().unwrap() else {
            return ControlFlow::Continue;
        };

        // The scanout_id validity is checked by DisplayBackendGtk, so we just assume it is valid
        // here
        match msg {
            DisplayEvent::ConfigureScanout {
                scanout_id,
                width,
                height,
                format,
            } => {
                let display_info = displays[scanout_id as usize]
                    .as_ref()
                    .expect("Invalid scanout_id");
                if let Some(ref mut scanout) = scanouts[scanout_id as usize] {
                    trace!("Update params of scanout {scanout_id}: width={width} height={height} format={format:?}");
                    scanout.update_params(width, height, format);
                } else {
                    debug!("Enable scanout {scanout_id} width={width} height={height} format={format:?}");
                    scanouts[scanout_id as usize] = Some(Scanout::new(
                        format!("{program_name} - display {scanout_id} ({width}x{height})"),
                        display_info.clone(),
                        width,
                        height,
                        format,
                    ));
                }
            }
            DisplayEvent::DisableScanout { scanout_id } => {
                debug!("Disable scanout {scanout_id}");
                scanouts[scanout_id as usize] = None;
            }
            DisplayEvent::UpdateScanout {
                scanout_id,
                data,
                stride,
            } => {
                if let Some(scanout) = &mut scanouts[scanout_id as usize] {
                    scanout.update(data, stride);
                } else {
                    warn!("Attempted to update non-existent scanout: {scanout_id}");
                }
            }
        };

        ControlFlow::Continue
    });

    main_loop.run();
}

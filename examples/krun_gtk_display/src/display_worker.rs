use std::cell::RefCell;
use std::os::fd::AsRawFd;
use std::rc::Rc;

use super::scanout_paintable::ScanoutPaintable;
use crate::DisplayEvent;
use krun_display::Rect;
use log::{debug, trace, warn};
use utils::pollable_channel::PollableChannelReciever;

use gtk::{
    AlertDialog, Align, Application, ApplicationWindow, Button, EventControllerMotion, HeaderBar,
    Overlay, Picture, Revealer, RevealerTransitionType, Window, gdk,
    gdk::MemoryFormat,
    gio::ActionEntry,
    gio::Cancellable,
    glib::{self, Bytes, ControlFlow, IOCondition, Propagation, unix_fd_add_local},
    prelude::*,
};
use krun_display::MAX_DISPLAYS;

struct ScanoutWindow {
    window: ApplicationWindow,
    width: i32,
    height: i32,
    format: MemoryFormat,
    scanout_paintable: ScanoutPaintable,
}

impl ScanoutWindow {
    pub fn new(
        app: &Application,
        title: &str,
        display_width: i32,
        display_height: i32,
        width: i32,
        height: i32,
        format: MemoryFormat,
    ) -> Self {
        let header_bar = HeaderBar::new();
        let window = ApplicationWindow::builder()
            .application(app)
            .title(title)
            .titlebar(&header_bar)
            .build();

        window.connect_close_request(|window| {
            let dialog = AlertDialog::builder()
                .buttons(["Kill VM", "Only close the window", "Cancel"].as_ref())
                .default_button(0)
                .cancel_button(2)
                .modal(true)
                .message("Do you want kill the VM?")
                .detail("WARNING: Killing the VM may lead to loss of data or corruption of the VM image.\n\n\
                If you only close the window the VM will keep running and rendering the display in the background.")
                .build();
            dialog.choose(Some(window), None::<&Cancellable>, glib::clone!(
                #[strong]
                window,
                move |b| match b {
                    Ok(0) => {
                        // SAFETY: Safe because we are terminating the process anyway.
                        // Currently, libkrun also uses _exit on normal VM exit, so we mimic that
                        // behavior here.
                        unsafe { libc::_exit(125) }
                    }
                    Ok(1) => {
                        window.set_visible(false);
                    },
                    Ok(2) => (),
                    Ok(_) => unreachable!("Unknown action"),
                    Err(e) => panic!("Failed to select option: {e}"),
                }
            ));
            Propagation::Stop
        });

        window.add_action_entries([
            ActionEntry::builder("fullscreen")
                .activate(move |window: &ApplicationWindow, _, _| window.fullscreen())
                .build(),
            ActionEntry::builder("unfullscreen")
                .activate(move |window: &ApplicationWindow, _, _| window.unfullscreen())
                .build(),
        ]);

        let fullscreen_btn = Button::builder()
            .icon_name("view-fullscreen")
            .tooltip_text("Enter fullscreen mode")
            .action_name("win.fullscreen")
            .build();

        let scanout_paintable = ScanoutPaintable::new(display_width, display_height);
        let picture = Picture::for_paintable(&scanout_paintable);

        window.set_titlebar(Some(&header_bar));
        header_bar.pack_end(&fullscreen_btn);

        let overlay = build_overlay(window.as_ref());
        overlay.set_child(Some(&picture));
        window.set_child(Some(&overlay));
        window.set_visible(true);

        Self {
            window,
            width,
            height,
            format,
            scanout_paintable,
        }
    }

    pub fn reconfigure(&mut self, width: i32, height: i32, format: gdk::MemoryFormat) {
        self.width = width;
        self.height = height;
        self.format = format;
    }

    pub fn update(&self, buffer: Bytes, rect: Option<Rect>) {
        self.scanout_paintable
            .update(buffer, self.width, self.height, self.format, rect);
    }
}

impl Drop for ScanoutWindow {
    fn drop(&mut self) {
        self.window.destroy();
    }
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
        .action_name("win.unfullscreen")
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

    overlay_bar.pack_end(&overlay_unfullscreen_btn);
    overlay_bar.set_show_title_buttons(false);

    overlay
}

pub struct DisplayWorker {
    app: Application,
    app_name: String,
    rx: PollableChannelReciever<DisplayEvent>,
    scanouts: RefCell<[Option<ScanoutWindow>; MAX_DISPLAYS]>,
}

impl DisplayWorker {
    pub fn new(
        app: Application,
        app_name: String,
        rx: PollableChannelReciever<DisplayEvent>,
    ) -> Self {
        Self {
            app,
            app_name,
            rx,
            scanouts: Default::default(),
        }
    }

    fn handle_event(&self) {
        let mut scanouts = self.scanouts.borrow_mut();
        while let Some(msg) = self.rx.try_recv().unwrap() {
            match msg {
                DisplayEvent::ConfigureScanout {
                    scanout_id,
                    display_width,
                    display_height,
                    width,
                    height,
                    format,
                } => {
                    if let Some(ref mut scanout) = scanouts[scanout_id as usize] {
                        trace!(
                            "Update params of scanout {scanout_id}: width={width} height={height} format={format:?}"
                        );
                        scanout.reconfigure(width as i32, height as i32, format);
                    } else {
                        debug!(
                            "Enable scanout {scanout_id} width={width} height={height} format={format:?}"
                        );
                        scanouts[scanout_id as usize] = Some(ScanoutWindow::new(
                            &self.app,
                            &format!(
                                "{name} - display {scanout_id} ({width}x{height})",
                                name = self.app_name
                            ),
                            display_width as i32,
                            display_height as i32,
                            width as i32,
                            height as i32,
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
                    buffer,
                    rect,
                } => {
                    if let Some(scanout) = &mut scanouts[scanout_id as usize] {
                        trace!("Update scanout {scanout_id}");
                        scanout.update(buffer, rect);
                    } else {
                        warn!("Attempted to update non-existent scanout: {scanout_id}");
                    }
                }
            }
        }
    }

    /// Run a GTK application in the current thread handling the krun_gtk_display events send over the channel.
    /// The events are produces by the `DisplayBackend` which is hooked up into libkrun.
    pub fn run(app_name: String, rx: PollableChannelReciever<DisplayEvent>) {
        let app = Application::builder().build();

        // Hold the application so it doesn't close when we don't have any windows open. We hold the
        // app forever, because currently libkrun just exits the process on VM shutdown so there is
        // no way for us to do anything better here for now.
        let _app_hold = app.hold();
        let rx_fd = rx.as_raw_fd();

        let display_worker = Rc::new(DisplayWorker::new(app.clone(), app_name, rx));
        app.connect_activate(move |_app| {
            let display_worker = display_worker.clone();
            unix_fd_add_local(rx_fd, IOCondition::IN, move |_, _| {
                display_worker.handle_event();
                ControlFlow::Continue
            });
        });
        app.run_with_args::<&str>(&[]);
    }
}

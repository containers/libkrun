use super::scanout_paintable::ScanoutPaintable;
use crate::{Axis, DisplayEvent, DisplayInputOptions, TouchArea, TouchScreenOptions};
use krun_display::Rect;
use krun_input::{InputEvent, InputEventType};
use log::{debug, trace, warn};
use std::cell::RefCell;
use std::collections::HashSet;
use std::iter;
use std::os::fd::AsRawFd;
use std::rc::Rc;
use std::time::Duration;

use utils::pollable_channel::{PollableChannelReciever, PollableChannelSender};

use crate::input_backend::{MAX_FINGERS, gtk_keycode_to_linux};
use crate::input_constants::{
    ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_SLOT, ABS_MT_TRACKING_ID, ABS_X, ABS_Y, BTN_TOUCH,
    SYN_REPORT,
};
use gtk::{
    AlertDialog, Align, Application, ApplicationWindow, Button, EventControllerKey,
    EventControllerLegacy, EventControllerMotion, HeaderBar, Overlay, Picture, Revealer,
    RevealerTransitionType, Widget, Window, gdk,
    gdk::{EventSequence, EventType, MemoryFormat, ModifierType, TouchEvent},
    gio::ActionEntry,
    gio::Cancellable,
    glib::{
        self, Bytes, ControlFlow, IOCondition, Propagation, clone::Downgrade,
        timeout_add_local_once, unix_fd_add_local,
    },
    graphene::Point,
    prelude::*,
};
use krun_display::MAX_DISPLAYS;

type EventSender = PollableChannelSender<InputEvent>;

#[derive(Debug)]
struct FingerState {
    seq: Option<EventSequence>,
    tracking_id: Option<u16>,
    pos: Option<(u32, u32)>,
}

#[derive(Debug, Default)]
struct FingerTracker {
    fingers: [Option<FingerState>; MAX_FINGERS],
}

impl FingerTracker {
    fn track(&mut self, seq: Option<EventSequence>) -> (u16, &mut FingerState) {
        let mut finger_idx = 0;
        let mut found_empty_slot = false;
        if let Some(seq) = &seq {
            for (idx, f) in self.fingers.iter_mut().enumerate() {
                match f {
                    Some(s) if s.seq.as_ref() == Some(seq) => {
                        finger_idx = idx;
                        break;
                    }
                    None if !found_empty_slot => {
                        finger_idx = idx;
                        found_empty_slot = true;
                    }
                    _ => continue,
                }
            }
        }

        match self.fingers[finger_idx] {
            Some(ref mut finger_state) => (finger_idx as u16, finger_state),
            None => {
                let finger_state = self.fingers[finger_idx].insert(FingerState {
                    seq: seq.clone(),
                    tracking_id: None,
                    pos: None,
                });
                (finger_idx as u16, finger_state)
            }
        }
    }

    fn get_by_id(&self, finger_idx: u16) -> Option<&FingerState> {
        self.fingers[finger_idx as usize].as_ref()
    }

    fn delete_by_idx(&mut self, finger_idx: u16) {
        self.fingers[finger_idx as usize] = None;
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TouchState {
    Begin,
    Update,
    End,
}

struct TouchEventSequencedSender {
    fingers: FingerTracker,
    synced_finger_zero_pos: (u32, u32),
    last_tracking_id: u16,
    active_finger_idx: u16,
    options: TouchScreenOptions,
    queue: Vec<InputEvent>,
    tx: EventSender,
    requested_deferred_sync: bool,
}

impl TouchEventSequencedSender {
    fn new(tx: EventSender, options: TouchScreenOptions) -> Self {
        Self {
            fingers: Default::default(),
            synced_finger_zero_pos: (0, 0),
            last_tracking_id: 0,
            active_finger_idx: u16::MAX,
            options,
            queue: Vec::new(),
            tx,
            requested_deferred_sync: true,
        }
    }

    fn sync(&mut self) {
        if self.queue.is_empty() {
            return;
        }
        self.requested_deferred_sync = false;

        let pending_events = [const {
            InputEvent {
                type_: 0,
                code: 0,
                value: 0,
            }
        }; 2];
        let mut pending_events_len = 0;

        if self.options.emit_non_mt
            && let Some(finger_pos) = self.fingers.get_by_id(0).and_then(|f| f.pos)
        {
            if finger_pos.0 != self.synced_finger_zero_pos.0 {
                self.queue.push(InputEvent {
                    type_: InputEventType::Abs as u16,
                    code: ABS_X,
                    value: finger_pos.0,
                });
                pending_events_len += 1;
            }

            if finger_pos.1 != self.synced_finger_zero_pos.1 {
                self.queue.push(InputEvent {
                    type_: InputEventType::Abs as u16,
                    code: ABS_Y,
                    value: finger_pos.1,
                });
                pending_events_len += 1;
            }
            self.synced_finger_zero_pos = finger_pos;
        }

        let final_sync_event = iter::once(InputEvent {
            type_: InputEventType::Syn as u16,
            code: SYN_REPORT,
            value: 0,
        });

        let input_events = self.queue.drain(..);

        let iter = pending_events[..pending_events_len].iter().copied();
        self.tx
            .send_many(input_events.chain(final_sync_event).chain(iter))
            .unwrap();
    }

    // Map GTK coordinates to the user specified ones
    fn map_position(
        TouchArea {
            x:
                Axis {
                    min: min_x,
                    max: max_x,
                    ..
                },
            y:
                Axis {
                    min: min_y,
                    max: max_y,
                    ..
                },
        }: TouchArea,
        (area_width, area_height): (i32, i32),
        (x, y): (f32, f32),
    ) -> (u32, u32) {
        let (x, y) = (x as f64, y as f64);
        debug!("{x} / {area_width} * ({max_x} - {min_x}) + {min_x}");
        debug!("{y} / {area_height} * ({max_y} - {min_y}) + {min_y}");
        let mapped_x = ((x / area_width as f64) * (max_x - min_x) as f64) + min_x as f64;
        let mapped_x = mapped_x.round() as u32;
        let mapped_y = ((y / area_height as f64) * (max_y - min_y) as f64) + min_y as f64;
        let mapped_y = mapped_y.round() as u32;

        // Clamp the coordinates to be sure the floating point rounding to be sure they cannot be
        // slightly out of bounds due to rounding
        (mapped_x.clamp(min_x, max_x), mapped_y.clamp(min_y, max_y))
    }

    // None passed as EventSequence implicitly means finger `0`
    // returns true fi a deffered sync should be scheduled
    fn push_event(
        &mut self,
        seq: Option<EventSequence>,
        state: TouchState,
        position: (f32, f32),
        touch_area_size: (i32, i32),
    ) -> bool {
        let (finger_idx, finger) = self.fingers.track(seq);
        let (x, y) = Self::map_position(self.options.area, touch_area_size, position);

        // Ignore other fingers if multitouch is disabled
        if !self.options.emit_mt && finger_idx != 0 {
            return false;
        }

        let (old_x, old_y) = finger
            .pos
            .map(|(x, y)| (Some(x), Some(y)))
            .unwrap_or((None, None));

        if self.options.emit_mt {
            if self.active_finger_idx != finger_idx {
                self.queue.push(InputEvent {
                    type_: InputEventType::Abs as u16,
                    code: ABS_MT_SLOT,
                    value: finger_idx as u32,
                });
                self.active_finger_idx = finger_idx;
            }

            if finger.tracking_id.is_none() {
                self.last_tracking_id = self.last_tracking_id.wrapping_add(1);
                finger.tracking_id = Some(self.last_tracking_id);
                self.queue.push(InputEvent {
                    type_: InputEventType::Abs as u16,
                    code: ABS_MT_TRACKING_ID,
                    value: self.last_tracking_id as u32,
                });
            }

            if old_x.is_none_or(|old_x| old_x != x) {
                self.queue.push(InputEvent {
                    type_: InputEventType::Abs as u16,
                    code: ABS_MT_POSITION_X,
                    value: x,
                });
            }

            if old_y.is_none_or(|old_y| old_y != y) {
                self.queue.push(InputEvent {
                    type_: InputEventType::Abs as u16,
                    code: ABS_MT_POSITION_Y,
                    value: y,
                });
            }
        }
        finger.pos = Some((x, y));

        match state {
            TouchState::Begin => {
                if self.options.emit_non_mt {
                    self.queue.push(InputEvent {
                        type_: InputEventType::Key as u16,
                        code: BTN_TOUCH,
                        value: 1,
                    });
                }
                self.sync();
                false
            }
            TouchState::End => {
                // Sync in case we have a position update to emit it separately
                self.sync();

                if self.options.emit_mt {
                    self.queue.push(InputEvent {
                        type_: InputEventType::Abs as u16,
                        code: ABS_MT_TRACKING_ID,
                        value: u32::MAX,
                    });
                }

                if self.options.emit_non_mt {
                    self.queue.push(InputEvent {
                        type_: InputEventType::Key as u16,
                        code: BTN_TOUCH,
                        value: 0,
                    });
                }

                self.fingers.delete_by_idx(finger_idx);
                self.sync();
                false
            }
            TouchState::Update => {
                if self.requested_deferred_sync {
                    false
                } else {
                    self.requested_deferred_sync = true;
                    true
                }
            }
        }
    }
}

struct ScanoutWindow {
    window: ApplicationWindow,
    width: i32,
    height: i32,
    format: MemoryFormat,
    scanout_paintable: ScanoutPaintable,
}

impl ScanoutWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app: &Application,
        title: &str,
        display_width: i32,
        display_height: i32,
        width: i32,
        height: i32,
        format: MemoryFormat,
        keyboard_event_tx: Option<EventSender>,
        per_display_inputs: Vec<(EventSender, DisplayInputOptions)>,
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
        if let Some(keyboard_event_tx) = keyboard_event_tx {
            attach_keyboard(keyboard_event_tx, &picture);
        }
        attach_per_display_inputs(&picture, window.as_ref(), per_display_inputs);

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

fn attach_keyboard(keyboard_tx: EventSender, widget: &impl IsA<Widget>) {
    let key_controller = EventControllerKey::new();

    // Handle key press events
    let forwarder_press = keyboard_tx.clone();
    let pressed_keys = Rc::new(RefCell::new(HashSet::new()));
    let pressed_keys_clone = pressed_keys.clone();
    key_controller.connect_key_pressed(move |_controller, key, keycode, _modifiers| {
        let linux_keycode = gtk_keycode_to_linux(keycode);
        if linux_keycode == 0 {
            debug!("Unknown key GTK key={}, code={}", key, keycode);
            return Propagation::Proceed;
        } else {
            debug!(
                "Forwarding key press: GTK key={}, code={}, Linux code={}",
                key, keycode, linux_keycode
            );
        }
        let is_first_keypress = pressed_keys_clone.borrow_mut().insert(linux_keycode);
        let input_event = InputEvent {
            type_: InputEventType::Key as u16,
            code: linux_keycode,
            value: if is_first_keypress { 1 } else { 2 },
        };
        forwarder_press.send(input_event).unwrap();
        let syn = InputEvent {
            type_: InputEventType::Syn as u16,
            code: SYN_REPORT,
            value: 0,
        };
        forwarder_press.send(syn).unwrap();
        Propagation::Proceed
    });

    // Handle key release events
    let forwarder_release = keyboard_tx.clone();
    key_controller.connect_key_released(move |_controller, key, keycode, _modifiers| {
        let linux_keycode = gtk_keycode_to_linux(keycode);
        let input_event = InputEvent {
            type_: InputEventType::Key as u16,
            code: linux_keycode,
            value: 0, // Key release
        };
        debug!(
            "Forwarding key release: GTK key={}, code={}, Linux code={}",
            key, keycode, linux_keycode
        );
        pressed_keys.borrow_mut().remove(&linux_keycode);

        forwarder_release.send(input_event).unwrap();
        // TODO: use send_many
        let syn = InputEvent {
            type_: InputEventType::Syn as u16,
            code: SYN_REPORT,
            value: 0,
        };
        forwarder_release.send(syn).unwrap();
    });
    widget.add_controller(key_controller);
}

fn attach_per_display_inputs(
    widget: &Picture,
    window: &Window,
    per_display_inputs: Vec<(EventSender, DisplayInputOptions)>,
) {
    for (tx, options) in per_display_inputs {
        match options {
            DisplayInputOptions::TouchScreen(options) => {
                let triggered_by_mouse = options.triggered_by_mouse;
                let input_controller = EventControllerLegacy::new();
                let touch_sender =
                    Rc::new(RefCell::new(TouchEventSequencedSender::new(tx, options)));

                let widget_weak = Downgrade::downgrade(widget);
                let window_weak = Downgrade::downgrade(window);

                input_controller.connect_event(move |_, event| {
                    let widget = widget_weak.upgrade().unwrap();
                    let window = window_weak.upgrade().unwrap();

                    let (x, y);
                    let state;
                    let seq;

                    if let Some(event) = event.downcast_ref::<TouchEvent>() {
                        (x, y) = event.position().unwrap();
                        state = match event.event_type() {
                            EventType::TouchBegin => TouchState::Begin,
                            EventType::TouchUpdate => TouchState::Update,
                            EventType::TouchEnd | EventType::TouchCancel => TouchState::End,
                            _ => return Propagation::Proceed,
                        };

                        seq = Some(event.event_sequence());
                    } else if let Some(event) = event.downcast_ref::<gdk::ButtonEvent>()
                        && triggered_by_mouse
                    {
                        (x, y) = event.position().unwrap();
                        state = match event.event_type() {
                            EventType::ButtonPress => TouchState::Begin,
                            EventType::ButtonRelease => TouchState::End,
                            _ => return Propagation::Proceed,
                        };
                        seq = None;
                    } else if let Some(event) = event.downcast_ref::<gdk::MotionEvent>()
                        && triggered_by_mouse
                        && event.modifier_state().contains(ModifierType::BUTTON1_MASK)
                    {
                        (x, y) = event.position().unwrap();
                        state = TouchState::Update;
                        seq = None;
                    } else {
                        return Propagation::Proceed;
                    }

                    let Some(point) =
                        window.compute_point(&widget, &Point::new(x as f32, y as f32))
                    else {
                        return Propagation::Proceed;
                    };

                    let (x, y) = (point.x(), point.y());

                    let requested_deferred_sync = touch_sender.borrow_mut().push_event(
                        seq,
                        state,
                        (x, y),
                        (widget.width(), widget.height()),
                    );

                    if requested_deferred_sync {
                        let touch_sender = touch_sender.clone();
                        timeout_add_local_once(Duration::from_millis(0), move || {
                            touch_sender.borrow_mut().sync();
                        });
                    }

                    Propagation::Stop
                });
                widget.add_controller(input_controller);
            }
        }
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
    keyboard_event_tx: Option<EventSender>,
    per_display_inputs: Vec<Vec<(PollableChannelSender<InputEvent>, DisplayInputOptions)>>,
    scanouts: RefCell<[Option<ScanoutWindow>; MAX_DISPLAYS]>,
}

impl DisplayWorker {
    pub fn new(
        app: Application,
        app_name: String,
        rx: PollableChannelReciever<DisplayEvent>,
        keyboard_event_tx: Option<EventSender>,
        per_display_inputs: Vec<Vec<(PollableChannelSender<InputEvent>, DisplayInputOptions)>>,
    ) -> Self {
        Self {
            app,
            app_name,
            rx,
            keyboard_event_tx,
            per_display_inputs,
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
                            self.keyboard_event_tx.clone(),
                            self.per_display_inputs
                                .get(scanout_id as usize)
                                .cloned()
                                .unwrap_or_default(),
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
    pub fn run(
        app_name: String,
        rx: PollableChannelReciever<DisplayEvent>,
        keyboard_tx: Option<EventSender>,
        per_display_inputs: Vec<Vec<(PollableChannelSender<InputEvent>, DisplayInputOptions)>>,
    ) {
        let app = Application::builder().build();

        // Hold the application so it doesn't close when we don't have any windows open. We hold the
        // app forever, because currently libkrun just exits the process on VM shutdown so there is
        // no way for us to do anything better here for now.
        let _app_hold = app.hold();
        let rx_fd = rx.as_raw_fd();

        let display_worker = Rc::new(DisplayWorker::new(
            app.clone(),
            app_name,
            rx,
            keyboard_tx,
            per_display_inputs,
        ));
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

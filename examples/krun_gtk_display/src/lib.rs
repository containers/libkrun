mod display_backend;
mod display_worker;
mod scanout_paintable;

use crate::display_worker::DisplayWorker;
use anyhow::Context;
pub use display_backend::DisplayEvent;
pub use display_backend::GtkDisplayBackend;
use krun_display::{DisplayBackend, IntoDisplayBackend};
use utils::pollable_channel::{PollableChannelReciever, PollableChannelSender, pollable_channel};

pub struct DisplayBackendHandle {
    tx: PollableChannelSender<DisplayEvent>,
}

impl DisplayBackendHandle {
    pub fn get(&self) -> DisplayBackend<'_> {
        GtkDisplayBackend::into_display_backend(Some(&self.tx))
    }
}

pub struct DisplayBackendWorker {
    app_name: String,
    rx: PollableChannelReciever<DisplayEvent>,
}

impl DisplayBackendWorker {
    /// NOTE: on macOS GTK has to run on the main thread of the application.
    pub fn run(self) {
        DisplayWorker::run(self.app_name, self.rx)
    }
}

pub fn crate_display(app_name: String) -> (DisplayBackendHandle, DisplayBackendWorker) {
    let (tx, rx) = pollable_channel()
        .context("Failed to create channel")
        .unwrap();

    (
        DisplayBackendHandle { tx },
        DisplayBackendWorker { app_name, rx },
    )
}

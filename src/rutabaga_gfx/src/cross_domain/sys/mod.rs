// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        pub(crate) mod unix;
        mod epoll_internal;
        use unix as platform;
    } else if #[cfg(any(target_os = "fuchsia",target_os = "windows", target_os = "macos"))] {
        pub(crate) mod stub;
        use stub as platform;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub use platform::channel;
pub use platform::channel_signal;
pub use platform::channel_wait;
pub use platform::descriptor_analysis;
pub use platform::read_volatile;
pub use platform::write_volatile;
pub use platform::Receiver;
pub use platform::Sender;
pub use platform::SystemStream;
pub use platform::WaitContext;

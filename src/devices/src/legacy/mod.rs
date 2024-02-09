// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
mod gic;
mod i8042;
#[cfg(target_arch = "aarch64")]
mod rtc_pl031;
#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
use x86_64::serial;
#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
use aarch64::gpio;
#[cfg(target_arch = "aarch64")]
use aarch64::serial;

#[cfg(target_os = "macos")]
pub use self::gic::Gic;
#[cfg(target_arch = "aarch64")]
pub use self::gpio::Gpio;
pub use self::i8042::Error as I8042DeviceError;
pub use self::i8042::I8042Device;
#[cfg(target_arch = "aarch64")]
pub use self::rtc_pl031::RTC;
pub use self::serial::Serial;

// Cannot use multiple types as bounds for a trait object, so we define our own trait
// which is a composition of the desired bounds. In this case, io::Read and AsRawFd.
// Run `rustc --explain E0225` for more details.
/// Trait that composes the `std::io::Read` and `std::os::unix::io::AsRawFd` traits.
pub trait ReadableFd: std::io::Read + std::os::fd::AsRawFd {}

#[cfg(target_os = "linux")]
pub struct Gic {}

#[cfg(target_os = "linux")]
impl Gic {
    pub fn set_irq(&mut self, _irq: u32) {}
}

// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![cfg(target_arch = "x86_64")]

use std::fmt;
use std::sync::{Arc, Mutex};

use devices;
use utils::eventfd::EventFd;

/// Errors corresponding to the `PortIODeviceManager`.
#[derive(Debug)]
pub enum Error {
    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),
    /// Cannot create EventFd.
    EventFd(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            BusError(ref err) => write!(f, "Failed to add legacy device to Bus: {err}"),
            EventFd(ref err) => write!(f, "Failed to create EventFd: {err}"),
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// The `PortIODeviceManager` is a wrapper that is used for registering legacy devices
/// on an I/O Bus. It currently manages the uart and i8042 devices.
/// The `LegacyDeviceManger` should be initialized only by using the constructor.
pub struct PortIODeviceManager {
    pub io_bus: devices::Bus,
    pub stdio_serial: Option<Arc<Mutex<devices::legacy::Serial>>>,
    pub i8042: Arc<Mutex<devices::legacy::I8042Device>>,

    pub com_evt_1_3: EventFd,
    pub com_evt_2_4: EventFd,
    pub kbd_evt: EventFd,
}

impl PortIODeviceManager {
    /// Create a new DeviceManager handling legacy devices (uart, i8042).
    pub fn new(
        stdio_serial: Option<Arc<Mutex<devices::legacy::Serial>>>,
        i8042_reset_evfd: EventFd,
    ) -> Result<Self> {
        let io_bus = devices::Bus::new();
        let com_evt_1_3 = if let Some(serial) = &stdio_serial {
            serial
                .lock()
                .unwrap()
                .interrupt_evt()
                .try_clone()
                .map_err(Error::EventFd)?
        } else {
            EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?
        };
        let com_evt_2_4 = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let kbd_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;

        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            i8042_reset_evfd,
            kbd_evt.try_clone().map_err(Error::EventFd)?,
        )));

        Ok(PortIODeviceManager {
            io_bus,
            stdio_serial,
            i8042,
            com_evt_1_3,
            com_evt_2_4,
            kbd_evt,
        })
    }

    /// Register supported legacy devices.
    pub fn register_devices(&mut self) -> Result<()> {
        if let Some(serial) = &self.stdio_serial {
            self.io_bus
                .insert(serial.clone(), 0x3f8, 0x8)
                .map_err(Error::BusError)?;
        }
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
                ))),
                0x2f8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_1_3.try_clone().map_err(Error::EventFd)?,
                ))),
                0x3e8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
                ))),
                0x2e8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(self.i8042.clone(), 0x060, 0x5)
            .map_err(Error::BusError)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_legacy_devices() {
        let serial =
            devices::legacy::Serial::new_sink(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
        let ldm = PortIODeviceManager::new(
            Some(Arc::new(Mutex::new(serial))),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        );
        assert!(ldm.is_ok());
        assert!(&ldm.unwrap().register_devices().is_ok());
    }

    #[test]
    fn test_debug_error() {
        assert_eq!(
            format!("{}", Error::BusError(devices::BusError::Overlap)),
            format!(
                "Failed to add legacy device to Bus: {}",
                devices::BusError::Overlap
            )
        );
        assert_eq!(
            format!("{}", Error::EventFd(std::io::Error::from_raw_os_error(1))),
            format!(
                "Failed to create EventFd: {}",
                std::io::Error::from_raw_os_error(1)
            )
        );
    }
}

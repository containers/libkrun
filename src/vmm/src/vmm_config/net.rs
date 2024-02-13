// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::os::fd::RawFd;
use std::result;
use std::sync::{Arc, Mutex};

use devices::virtio::Net;

#[derive(Debug, PartialEq)]
//#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceConfig {
    /// ID of the guest network interface.
    pub iface_id: String,
    /// File descriptor of passt socket to connect this interface to
    pub passt_fd: RawFd,
    /// MAC address.
    pub mac: [u8; 6],
}

/// Errors associated with `NetworkInterfaceConfig`.
#[derive(Debug)]
pub enum NetworkInterfaceError {
    /// Could not create Network Device.
    CreateNetworkDevice(devices::virtio::net::Error),
    /// Couldn't find the interface to update (patch).
    DeviceIdNotFound,
}

impl fmt::Display for NetworkInterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::NetworkInterfaceError::*;
        match *self {
            CreateNetworkDevice(ref e) => write!(f, "Could not create Network Device: {:?}", e),
            DeviceIdNotFound => write!(f, "Invalid interface ID - not found."),
        }
    }
}

type Result<T> = result::Result<T, NetworkInterfaceError>;

/// Builder for a list of network devices.
#[derive(Default)]
pub struct NetBuilder {
    net_devices: Vec<Arc<Mutex<Net>>>,
}

impl NetBuilder {
    /// Creates an empty list of Network Devices.
    pub fn new() -> Self {
        NetBuilder {
            // List of built network devices.
            net_devices: Vec::new(),
        }
    }

    /// Returns a immutable iterator over the network devices.
    pub fn iter(&self) -> ::std::slice::Iter<Arc<Mutex<Net>>> {
        self.net_devices.iter()
    }

    /// Returns a mutable iterator over the network devices.
    pub fn iter_mut(&mut self) -> ::std::slice::IterMut<Arc<Mutex<Net>>> {
        self.net_devices.iter_mut()
    }

    /// Builds a network device based on a network interface config. Keeps a device reference
    /// in the builder's internal list.
    pub fn build(&mut self, netif_config: NetworkInterfaceConfig) -> Result<Arc<Mutex<Net>>> {
        // If this is an update, just remove the old one.
        if let Some(index) = self
            .net_devices
            .iter()
            .position(|net| net.lock().expect("Poisoned lock").id() == netif_config.iface_id)
        {
            self.net_devices.swap_remove(index);
        }

        // Add new device.
        let net = Arc::new(Mutex::new(Self::create_net(netif_config)?));
        self.net_devices.push(net.clone());

        Ok(net)
    }

    /// Creates a Net device from a NetworkInterfaceConfig.
    pub fn create_net(cfg: NetworkInterfaceConfig) -> Result<Net> {
        // Create and return the Net device
        Net::new(cfg.iface_id, cfg.passt_fd, cfg.mac)
            .map_err(NetworkInterfaceError::CreateNetworkDevice)
    }
}

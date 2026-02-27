// Copyright 2026, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic vhost-user device wrapper.
//!
//! This module provides a wrapper around the vhost crate's Frontend,
//! adapting it to work with libkrun's VirtioDevice trait.

use std::io::{self, ErrorKind, Result as IoResult};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;

use log::{debug, error};
use utils::eventfd::EventFd;
use vhost::vhost_user::{Frontend, VhostUserFrontend, VhostUserProtocolFeatures};
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    VirtioDevice,
};

/// VHOST_USER_F_PROTOCOL_FEATURES (bit 30) is a backend-only feature
/// that enables vhost-user protocol extensions. It's not a virtio feature.
const VHOST_USER_F_PROTOCOL_FEATURES: u64 = 1 << 30;

/// Translate a guest physical address to a VMM virtual address.
fn gpa_to_vmm_va(mem: &GuestMemoryMmap, gpa: u64) -> IoResult<u64> {
    for region in mem.iter() {
        let region_start = region.start_addr().raw_value();
        let region_end = region_start + region.len();

        if gpa >= region_start && gpa < region_end {
            let offset = gpa - region_start;
            let vmm_va = region.as_ptr() as u64 + offset;
            return Ok(vmm_va);
        }
    }

    Err(io::Error::new(
        ErrorKind::InvalidInput,
        format!("GPA 0x{:x} not found in any memory region", gpa),
    ))
}

/// Generic vhost-user device wrapper.
///
/// This wraps a vhost-user backend connection and implements the VirtioDevice
/// trait, allowing it to be used like any other virtio device in libkrun.
pub struct VhostUserDevice {
    /// Vhost-user frontend connection
    frontend: Arc<Mutex<Frontend>>,

    /// Device type (e.g., VIRTIO_ID_RNG = 4)
    device_type: u32,

    /// Device name for logging
    device_name: String,

    /// Queue configurations
    queue_configs: Vec<QueueConfig>,

    /// Available features from the backend
    avail_features: u64,

    /// Whether the backend supports protocol features
    has_protocol_features: bool,

    /// Acknowledged features
    acked_features: u64,

    /// Device state
    device_state: DeviceState,
}

impl VhostUserDevice {
    /// Create a new vhost-user device by connecting to a socket.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the vhost-user Unix domain socket
    /// * `device_type` - Virtio device type ID
    /// * `device_name` - Human-readable device name for logging
    /// * `num_queues` - Number of queues (0 = query backend via MQ protocol)
    /// * `queue_sizes` - Size for each queue (empty = use default 256)
    ///
    /// # Returns
    ///
    /// A new VhostUserDevice or an error if connection fails.
    pub fn new(
        socket_path: &str,
        device_type: u32,
        device_name: String,
        num_queues: u16,
        queue_sizes: &[u16],
    ) -> IoResult<Self> {
        debug!("Connecting to vhost-user backend at {}", socket_path);

        // Connect to the vhost-user backend
        let stream = UnixStream::connect(socket_path)?;
        // NOTE: `num_queues` could be 0 here, but this is actually fine
        // because if `VhostUserProtocolFeatures::MQ` is supported the negotiated
        // value will be used automatically by Frontend
        let mut frontend = Frontend::from_stream(stream, num_queues as u64);

        // Get available features from backend
        let avail_features = frontend
            .get_features()
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        debug!("{}: backend features: 0x{:x}", device_name, avail_features);

        // Strip the vhost specific bit to leave only standard virtio features
        let has_protocol_features = avail_features & VHOST_USER_F_PROTOCOL_FEATURES != 0;
        let avail_features = avail_features & !VHOST_USER_F_PROTOCOL_FEATURES;

        if has_protocol_features {
            let protocol_features = frontend
                .get_protocol_features()
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

            let mut our_protocol_features = VhostUserProtocolFeatures::empty();
            if protocol_features.contains(VhostUserProtocolFeatures::CONFIG) {
                our_protocol_features |= VhostUserProtocolFeatures::CONFIG;
            }
            if protocol_features.contains(VhostUserProtocolFeatures::MQ) {
                our_protocol_features |= VhostUserProtocolFeatures::MQ;
            }

            frontend
                .set_protocol_features(our_protocol_features)
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        }

        // Determine actual queue count - may require protocol feature negotiation
        let actual_num_queues = if num_queues == 0 {
            if has_protocol_features {
                let backend_queue_num = frontend
                    .get_queue_num()
                    .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

                debug!(
                    "{}: backend reports {} queues available",
                    device_name, backend_queue_num
                );

                backend_queue_num as usize
            } else {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "Backend doesn't support protocol features, must specify queue count",
                ));
            }
        } else {
            num_queues as usize
        };

        debug!(
            "{}: using {} queues (requested: {}, sizes provided: {})",
            device_name,
            actual_num_queues,
            num_queues,
            queue_sizes.len()
        );

        let default_size = queue_sizes.last().copied().unwrap_or(256);
        let queue_configs: Vec<_> = (0..actual_num_queues)
            .map(|i| {
                let size = queue_sizes.get(i).copied().unwrap_or(default_size);
                QueueConfig::new(size)
            })
            .collect();

        Ok(VhostUserDevice {
            frontend: Arc::new(Mutex::new(frontend)),
            device_type,
            device_name,
            queue_configs,
            avail_features,
            has_protocol_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
        })
    }

    /// Activate the vhost-user device by setting up memory and vrings.
    fn activate_vhost_user(
        &mut self,
        mem: &GuestMemoryMmap,
        interrupt: &InterruptTransport,
        queues: &[DeviceQueue],
    ) -> IoResult<()> {
        let mut frontend = self.frontend.lock().unwrap();

        debug!("{}: activating vhost-user device", self.device_name);

        // Combine guest-acked features with backend-only features (QEMU approach)
        let backend_feature_bits = if self.has_protocol_features {
            self.acked_features | VHOST_USER_F_PROTOCOL_FEATURES
        } else {
            self.acked_features
        };

        frontend
            .set_owner()
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        // Only share memory regions that have file backing (memfd)
        let regions: Vec<VhostUserMemoryRegionInfo> = mem
            .iter()
            .filter_map(|region| {
                if region.file_offset().is_some() {
                    Some(VhostUserMemoryRegionInfo::from_guest_region(region))
                } else {
                    None
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                error!(
                    "{}: failed to convert memory regions: {:?}",
                    self.device_name, e
                );
                io::Error::new(ErrorKind::Other, e)
            })?;

        debug!(
            "{}: sharing {} file-backed regions with backend",
            self.device_name,
            regions.len()
        );

        frontend.set_mem_table(&regions).map_err(|e| {
            error!("{}: set_mem_table failed: {:?}", self.device_name, e);
            io::Error::new(ErrorKind::Other, e)
        })?;

        // If protocol features not negotiated, this triggers automatic ring enabling
        frontend
            .set_features(backend_feature_bits)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        // Create single vring call event file descriptor (backend->guest interrupt)
        // NOTE: Do NOT use EFD_NONBLOCK here - the monitoring thread needs to block
        let vring_call_event = EventFd::new(0)?; // Blocking eventfd

        for (queue_index, device_queue) in queues.iter().enumerate() {
            let queue = &device_queue.queue;

            frontend
                .set_vring_num(queue_index, queue.actual_size())
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

            // Set vring base
            frontend
                .set_vring_base(queue_index, 0)
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

            // Vring addresses in queue are GPAs, but vhost-user protocol expects VMM VAs
            let desc_table_gpa = queue.desc_table.0;
            let avail_ring_gpa = queue.avail_ring.0;
            let used_ring_gpa = queue.used_ring.0;

            let desc_table_vmm = gpa_to_vmm_va(mem, desc_table_gpa)?;
            let avail_ring_vmm = gpa_to_vmm_va(mem, avail_ring_gpa)?;
            let used_ring_vmm = gpa_to_vmm_va(mem, used_ring_gpa)?;

            let vring_config = VringConfigData {
                flags: 0,
                queue_max_size: queue.get_max_size(),
                queue_size: queue.actual_size(),
                desc_table_addr: desc_table_vmm,
                used_ring_addr: used_ring_vmm,
                avail_ring_addr: avail_ring_vmm,
                log_addr: None,
            };

            frontend
                .set_vring_addr(queue_index, &vring_config)
                .map_err(|e| {
                    error!("{}: set_vring_addr failed: {:?}", self.device_name, e);
                    io::Error::new(ErrorKind::Other, e)
                })?;

            frontend
                .set_vring_kick(queue_index, &device_queue.event)
                .map_err(|e| {
                    error!("{}: set_vring_kick failed: {:?}", self.device_name, e);
                    io::Error::new(ErrorKind::Other, e)
                })?;

            frontend
                .set_vring_call(queue_index, &vring_call_event)
                .map_err(|e| {
                    error!("{}: set_vring_call failed: {:?}", self.device_name, e);
                    io::Error::new(ErrorKind::Other, e)
                })?;

            // Per QEMU vhost.c: when VHOST_USER_F_PROTOCOL_FEATURES is not negotiated,
            // the rings start directly in the enabled state, and set_vring_enable will fail.
            if self.has_protocol_features {
                frontend
                    .set_vring_enable(queue_index, true)
                    .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
            } else {
                debug!(
                    "{}: vring {} already enabled (protocol features not negotiated)",
                    self.device_name, queue_index
                );
            }
        }

        // Spawn single interrupt monitoring thread
        // All queues share the same vring_call_event, so we only need one thread
        // to monitor it and forward interrupts to the guest
        let vring_call_event = vring_call_event.try_clone().map_err(|e| {
            io::Error::new(
                ErrorKind::Other,
                format!("Failed to clone vring_call_event: {}", e),
            )
        })?;
        let interrupt_clone = interrupt.clone();
        let device_name = self.device_name.clone();

        thread::Builder::new()
            .name(format!("{}_interrupt_monitor", self.device_name))
            .spawn(move || {
                debug!("{}: interrupt monitor thread started", device_name);
                loop {
                    // Wait for backend to signal interrupt from any queue
                    match vring_call_event.read() {
                        Ok(_) => {
                            debug!(
                                "{}: interrupt received from backend, signaling guest",
                                device_name
                            );
                            interrupt_clone.signal_used_queue();
                        }
                        Err(e) => {
                            error!("{}: interrupt monitor error: {}", device_name, e);
                            break;
                        }
                    }
                }
                debug!("{}: interrupt monitor thread exiting", device_name);
            })
            .map_err(|e| {
                io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to spawn interrupt monitor thread: {}", e),
                )
            })?;

        debug!(
            "{}: vhost-user device activated successfully",
            self.device_name
        );

        Ok(())
    }
}

impl VirtioDevice for VhostUserDevice {
    fn device_type(&self) -> u32 {
        self.device_type
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &self.queue_configs
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // For now, configuration space reads are not supported
        // This can be extended using VHOST_USER_GET_CONFIG
        debug!(
            "{}: config read at offset {} (not yet implemented)",
            self.device_name, offset
        );
        data.fill(0);
    }

    fn write_config(&mut self, offset: u64, _data: &[u8]) {
        // For now, configuration space writes are not supported
        // This can be extended using VHOST_USER_SET_CONFIG
        debug!(
            "{}: config write at offset {} (not yet implemented)",
            self.device_name, offset
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if let Err(e) = self.activate_vhost_user(&mem, &interrupt, &queues) {
            error!(
                "{}: failed to activate vhost-user device: {}",
                self.device_name, e
            );
            return Err(ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        matches!(self.device_state, DeviceState::Activated(_, _))
    }

    fn reset(&mut self) -> bool {
        debug!("{}: resetting vhost-user device", self.device_name);

        // Disable all vrings
        if let Ok(mut frontend) = self.frontend.lock() {
            for queue_index in 0..self.queue_configs.len() {
                if let Err(e) = frontend.set_vring_enable(queue_index, false) {
                    debug!(
                        "{}: failed to disable vring {} during reset: {}",
                        self.device_name, queue_index, e
                    );
                }
            }
        }

        self.device_state = DeviceState::Inactive;
        true
    }
}

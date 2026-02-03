// Copyright 2026, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Vhost-user device implementations for libkrun.
//!
//! This module provides vhost-user frontend support, allowing virtio devices
//! to run in separate processes for better isolation and flexibility.

mod device;

pub use device::VhostUserDevice;

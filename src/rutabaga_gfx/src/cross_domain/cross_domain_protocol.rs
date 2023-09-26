// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Hand-written protocol for the cross-domain context type.  Intended to be shared with C/C++
//! components.

#![allow(dead_code)]

use zerocopy::AsBytes;
use zerocopy::FromBytes;

/// Cross-domain commands (only a maximum of 255 supported)
pub const CROSS_DOMAIN_CMD_INIT: u8 = 1;
pub const CROSS_DOMAIN_CMD_GET_IMAGE_REQUIREMENTS: u8 = 2;
pub const CROSS_DOMAIN_CMD_POLL: u8 = 3;
pub const CROSS_DOMAIN_CMD_SEND: u8 = 4;
pub const CROSS_DOMAIN_CMD_RECEIVE: u8 = 5;
pub const CROSS_DOMAIN_CMD_READ: u8 = 6;
pub const CROSS_DOMAIN_CMD_WRITE: u8 = 7;

/// Channel types (must match rutabaga channel types)
pub const CROSS_DOMAIN_CHANNEL_TYPE_WAYLAND: u32 = 0x0001;
pub const CROSS_DOMAIN_CHANNEL_TYPE_CAMERA: u32 = 0x0002;

/// The maximum number of identifiers (value inspired by wp_linux_dmabuf)
pub const CROSS_DOMAIN_MAX_IDENTIFIERS: usize = 4;

/// virtgpu memory resource ID.  Also works with non-blob memory resources, despite the name.
pub const CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB: u32 = 1;
/// virtgpu synchronization resource id.
pub const CROSS_DOMAIN_ID_TYPE_VIRTGPU_SYNC: u32 = 2;
/// ID for Wayland pipe used for reading.  The reading is done by the guest proxy and the host
/// proxy.  The host sends the write end of the proxied pipe over the host Wayland socket.
pub const CROSS_DOMAIN_ID_TYPE_READ_PIPE: u32 = 3;
/// ID for Wayland pipe used for writing.  The writing is done by the guest and the host proxy.
/// The host receives the write end of the pipe over the host Wayland socket.
pub const CROSS_DOMAIN_ID_TYPE_WRITE_PIPE: u32 = 4;

/// No ring
pub const CROSS_DOMAIN_RING_NONE: u32 = 0xffffffff;
/// A ring for metadata queries.
pub const CROSS_DOMAIN_QUERY_RING: u32 = 0;
/// A ring based on this particular context's channel.
pub const CROSS_DOMAIN_CHANNEL_RING: u32 = 1;

/// Read pipe IDs start at this value.
pub const CROSS_DOMAIN_PIPE_READ_START: u32 = 0x80000000;

#[repr(C)]
#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
pub struct CrossDomainCapabilities {
    pub version: u32,
    pub supported_channels: u32,
    pub supports_dmabuf: u32,
    pub supports_external_gpu_memory: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
pub struct CrossDomainImageRequirements {
    pub strides: [u32; 4],
    pub offsets: [u32; 4],
    pub modifier: u64,
    pub size: u64,
    pub blob_id: u32,
    pub map_info: u32,
    pub memory_idx: i32,
    pub physical_device_idx: i32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
pub struct CrossDomainHeader {
    pub cmd: u8,
    pub ring_idx: u8,
    pub cmd_size: u16,
    pub pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
pub struct CrossDomainInit {
    pub hdr: CrossDomainHeader,
    pub query_ring_id: u32,
    pub channel_ring_id: u32,
    pub channel_type: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
pub struct CrossDomainGetImageRequirements {
    pub hdr: CrossDomainHeader,
    pub width: u32,
    pub height: u32,
    pub drm_format: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
pub struct CrossDomainSendReceive {
    pub hdr: CrossDomainHeader,
    pub num_identifiers: u32,
    pub opaque_data_size: u32,
    pub identifiers: [u32; CROSS_DOMAIN_MAX_IDENTIFIERS],
    pub identifier_types: [u32; CROSS_DOMAIN_MAX_IDENTIFIERS],
    pub identifier_sizes: [u32; CROSS_DOMAIN_MAX_IDENTIFIERS],
    // Data of size "opaque data size follows"
}

#[repr(C)]
#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
pub struct CrossDomainReadWrite {
    pub hdr: CrossDomainHeader,
    pub identifier: u32,
    pub hang_up: u32,
    pub opaque_data_size: u32,
    pub pad: u32,
    // Data of size "opaque data size follows"
}

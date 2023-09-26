// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VIRTGPU_CROSS_DOMAIN_PROTOCOL_H
#define VIRTGPU_CROSS_DOMAIN_PROTOCOL_H

#include <stdint.h>

// Cross-domain commands (only a maximum of 255 supported)
#define CROSS_DOMAIN_CMD_INIT 1
#define CROSS_DOMAIN_CMD_GET_IMAGE_REQUIREMENTS 2
#define CROSS_DOMAIN_CMD_POLL 3
#define CROSS_DOMAIN_CMD_SEND 4
#define CROSS_DOMAIN_CMD_RECEIVE 5
#define CROSS_DOMAIN_CMD_READ 6
#define CROSS_DOMAIN_CMD_WRITE 7

// Channel types (must match rutabaga channel types)
#define CROSS_DOMAIN_CHANNEL_TYPE_WAYLAND 0x0001
#define CROSS_DOMAIN_CHANNEL_TYPE_CAMERA 0x0002

// The maximum number of identifiers (value based on wp_linux_dmabuf)
#define CROSS_DOMAIN_MAX_IDENTIFIERS 4

// virtgpu memory resource ID.  Also works with non-blob memory resources,
// despite the name.
#define CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB 1

// virtgpu synchronization resource id.
#define CROSS_DOMAIN_ID_TYPE_VIRTGPU_SYNC 2

// ID for Wayland pipe used for reading.  The reading is done by the guest proxy
// and the host proxy.  The host sends the write end of the proxied pipe over
// the host Wayland socket.
#define CROSS_DOMAIN_ID_TYPE_READ_PIPE 3

// ID for Wayland pipe used for writing.  The writing is done by the guest and
// the host proxy. The host receives the write end of the pipe over the host
// Wayland socket.
#define CROSS_DOMAIN_ID_TYPE_WRITE_PIPE 4

// No ring used
#define CROSS_DOMAIN_RING_NONE 0xffffffff
// A ring for metadata queries.
#define CROSS_DOMAIN_QUERY_RING 0
// A ring based on this particular context's channel.
#define CROSS_DOMAIN_CHANNEL_RING 1

// Read pipe IDs start at this value.
#define CROSS_DOMAIN_PIPE_READ_START 0x80000000

struct CrossDomainCapabilities {
    uint32_t version;
    uint32_t supported_channels;
    uint32_t supports_dmabuf;
    uint32_t supports_external_gpu_memory;
};

struct CrossDomainImageRequirements {
    uint32_t strides[4];
    uint32_t offsets[4];
    uint64_t modifier;
    uint64_t size;
    uint32_t blob_id;
    uint32_t map_info;
    int32_t memory_idx;
    int32_t physical_device_idx;
};

struct CrossDomainHeader {
    uint8_t cmd;
    uint8_t fence_ctx_idx;
    uint16_t cmd_size;
    uint32_t pad;
};

struct CrossDomainInit {
    struct CrossDomainHeader hdr;
    uint32_t query_ring_id;
    uint32_t channel_ring_id;
    uint32_t channel_type;
};

struct CrossDomainGetImageRequirements {
    struct CrossDomainHeader hdr;
    uint32_t width;
    uint32_t height;
    uint32_t drm_format;
    uint32_t flags;
};

struct CrossDomainPoll {
    struct CrossDomainHeader hdr;
    uint64_t pad;
};

struct CrossDomainSendReceive {
    struct CrossDomainHeader hdr;
    uint32_t num_identifiers;
    uint32_t opaque_data_size;
    uint32_t identifiers[CROSS_DOMAIN_MAX_IDENTIFIERS];
    uint32_t identifier_types[CROSS_DOMAIN_MAX_IDENTIFIERS];
    uint32_t identifier_sizes[CROSS_DOMAIN_MAX_IDENTIFIERS];
};

struct CrossDomainReadWrite {
    struct CrossDomainHeader hdr;
    uint32_t identifier;
    uint32_t hang_up;
    uint32_t opaque_data_size;
    uint32_t pad;
};

#endif

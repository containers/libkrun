/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rutabaga_gfx/rutabaga_gfx_ffi.h>

#include "virtgpu_cross_domain_protocol.h"

#define CHECK_RESULT(result)                                                                       \
    do {                                                                                           \
        if (result) {                                                                              \
            printf("CHECK_RESULT failed in %s() %s:%d\n", __func__, __FILE__, __LINE__);           \
            return result;                                                                         \
        }                                                                                          \
    } while (0)

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("CHECK failed in %s() %s:%d\n", __func__, __FILE__, __LINE__);                  \
            return -EINVAL;                                                                        \
        }                                                                                          \
    } while (0)

#define DEFAULT_BUFFER_SIZE 4096
#define WIDTH 512
#define HEIGHT 512
#define NUM_ITERATIONS 4

#define GBM_BO_USE_LINEAR (1 << 4)
#define GBM_BO_USE_SCANOUT (1 << 5)
#define fourcc_code(a, b, c, d)                                                                    \
    ((uint32_t)(a) | ((uint32_t)(b) << 8) | ((uint32_t)(c) << 16) | ((uint32_t)(d) << 24))
#define DRM_FORMAT_XRGB8888 fourcc_code('X', 'R', '2', '4');

#define PIPE_TEXTURE_2D 2
#define PIPE_BIND_RENDER_TARGET 2
#define VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM 1

static int s_resource_id = 1;
static int s_fence_id = 1;

#if defined(__linux__)
static char *s_wayland_path = "/run/user/1000/wayland-0";
#elif defined(__Fuchsia__)
#endif

struct rutabaga_test {
    struct rutabaga *rutabaga;
    uint32_t ctx_id;
    uint64_t value;
    uint32_t query_ring_id;
    uint32_t channel_ring_id;
    struct iovec *query_iovecs;
    struct iovec *channel_iovecs;
};

static void rutabaga_test_write_fence(uint64_t user_data, const struct rutabaga_fence *fence)
{
    struct rutabaga_test *test = (void *)(uintptr_t)user_data;
    test->value = fence->fence_id;
}

static void rutabaga_test_debug_cb(uint64_t user_data, const struct rutabaga_debug *debug)
{
    if (debug->message) {
        printf("The debug message is %s\n", debug->message);
    }
}

static int test_capset_mask_calculation(void)
{
    int result;
    uint64_t capset_mask;

    result = rutabaga_calculate_capset_mask("cross-domain:gfxstream-vulkan", &capset_mask);
    CHECK_RESULT(result);
    CHECK(capset_mask ==
          ((1 << RUTABAGA_CAPSET_CROSS_DOMAIN) | (1 << RUTABAGA_CAPSET_GFXSTREAM_VULKAN)));

    result = rutabaga_calculate_capset_mask(":gfxstream-vulkan", &capset_mask);
    CHECK_RESULT(result);
    CHECK(capset_mask == (1 << RUTABAGA_CAPSET_GFXSTREAM_VULKAN));

    result = rutabaga_calculate_capset_mask("cross-domain:", &capset_mask);
    CHECK_RESULT(result);
    CHECK(capset_mask == (1 << RUTABAGA_CAPSET_CROSS_DOMAIN));

    result = rutabaga_calculate_capset_mask("cross-domain", &capset_mask);
    CHECK_RESULT(result);
    CHECK(capset_mask == (1 << RUTABAGA_CAPSET_CROSS_DOMAIN));

    result = rutabaga_calculate_capset_mask(":", &capset_mask);
    CHECK_RESULT(result);
    CHECK(capset_mask == 0);

    result = rutabaga_calculate_capset_mask("fake", &capset_mask);
    CHECK_RESULT(result);
    CHECK(capset_mask == 0);

    result = rutabaga_calculate_capset_mask("", &capset_mask);
    CHECK_RESULT(result);
    CHECK(capset_mask == 0);

    result = rutabaga_calculate_capset_mask(NULL, &capset_mask);
    CHECK(result != 0);

    return 0;
}

static int test_rutabaga_init(struct rutabaga_test *test, uint64_t capset_mask)
{
    int result;
    struct rutabaga_builder builder = { 0 };
    struct rutabaga_channels channels = { 0 };

    builder.fence_cb = rutabaga_test_write_fence;
    builder.debug_cb = rutabaga_test_debug_cb;
    builder.capset_mask = capset_mask;
    builder.wsi = RUTABAGA_WSI_SURFACELESS;
    if (capset_mask & (1 << RUTABAGA_CAPSET_CROSS_DOMAIN)) {
        builder.user_data = (uint64_t)(uintptr_t *)(void *)test;
        channels.channels = (struct rutabaga_channel *)calloc(1, sizeof(struct rutabaga_channel));
        channels.num_channels = 1;

        channels.channels[0].channel_name = s_wayland_path;
        channels.channels[0].channel_type = RUTABAGA_CHANNEL_TYPE_WAYLAND;

        builder.channels = &channels;
    }

    result = rutabaga_init(&builder, &test->rutabaga);

    if (capset_mask & (1 << RUTABAGA_CAPSET_CROSS_DOMAIN))
        free(channels.channels);

    CHECK_RESULT(result);
    return 0;
}

static int test_create_context(struct rutabaga_test *test, const char *context_name)
{
    int result;
    uint32_t num_capsets;
    uint32_t capset_id, capset_version, capset_size;
    bool found_cross_domain = false;
    struct CrossDomainCapabilities *capset;

    result = rutabaga_get_num_capsets(test->rutabaga, &num_capsets);
    CHECK_RESULT(result);
    CHECK(num_capsets == 1);

    for (uint32_t i = 0; i < num_capsets; i++) {
        result =
            rutabaga_get_capset_info(test->rutabaga, i, &capset_id, &capset_version, &capset_size);
        CHECK_RESULT(result);
        if (capset_id == RUTABAGA_CAPSET_CROSS_DOMAIN) {
            found_cross_domain = true;
            CHECK(capset_size == (uint32_t)sizeof(struct CrossDomainCapabilities));
        }
    }

    CHECK(found_cross_domain);
    CHECK_RESULT(result);

    capset = (struct CrossDomainCapabilities *)calloc(1, capset_size);
    result = rutabaga_get_capset(test->rutabaga, RUTABAGA_CAPSET_CROSS_DOMAIN, 0, (uint8_t *)capset,
                                 capset_size);
    CHECK_RESULT(result);

    CHECK(capset->version == 1);
    free(capset);

    size_t context_name_len = 0;
    if (context_name)
        context_name_len = strlen(context_name);

    result = rutabaga_context_create(test->rutabaga, test->ctx_id, RUTABAGA_CAPSET_CROSS_DOMAIN,
                                     context_name, context_name_len);
    CHECK_RESULT(result);

    return 0;
}

static int test_init_context(struct rutabaga_test *test)
{
    int result;
    struct rutabaga_create_blob rc_blob = { 0 };
    struct rutabaga_iovecs vecs = { 0 };
    struct rutabaga_command cmd = { 0 };
    struct CrossDomainInit cmd_init = { { 0 } };

    struct iovec *query_iovecs = (struct iovec *)calloc(1, sizeof(struct iovec));
    query_iovecs[0].iov_base = calloc(1, DEFAULT_BUFFER_SIZE);
    query_iovecs[0].iov_len = DEFAULT_BUFFER_SIZE;

    test->query_iovecs = query_iovecs;
    rc_blob.blob_mem = RUTABAGA_BLOB_MEM_GUEST;
    rc_blob.blob_flags = RUTABAGA_BLOB_FLAG_USE_MAPPABLE;
    rc_blob.size = DEFAULT_BUFFER_SIZE;

    vecs.iovecs = query_iovecs;
    vecs.num_iovecs = 1;

    result = rutabaga_resource_create_blob(test->rutabaga, 0, test->query_ring_id, &rc_blob, &vecs,
                                           NULL);
    CHECK_RESULT(result);

    result = rutabaga_context_attach_resource(test->rutabaga, test->ctx_id, test->query_ring_id);
    CHECK_RESULT(result);

    struct iovec *channel_iovecs = (struct iovec *)calloc(1, sizeof(struct iovec));
    channel_iovecs[0].iov_base = calloc(1, DEFAULT_BUFFER_SIZE);
    channel_iovecs[0].iov_len = DEFAULT_BUFFER_SIZE;

    test->channel_iovecs = channel_iovecs;
    rc_blob.blob_mem = RUTABAGA_BLOB_MEM_GUEST;
    rc_blob.blob_flags = RUTABAGA_BLOB_FLAG_USE_MAPPABLE;
    rc_blob.size = DEFAULT_BUFFER_SIZE;

    vecs.iovecs = channel_iovecs;
    vecs.num_iovecs = 1;

    result = rutabaga_resource_create_blob(test->rutabaga, 0, test->channel_ring_id, &rc_blob,
                                           &vecs, NULL);
    CHECK_RESULT(result);

    result = rutabaga_context_attach_resource(test->rutabaga, test->ctx_id, test->channel_ring_id);
    CHECK_RESULT(result);

    cmd_init.hdr.cmd = CROSS_DOMAIN_CMD_INIT;
    cmd_init.hdr.cmd_size = sizeof(struct CrossDomainInit);
    cmd_init.query_ring_id = test->query_ring_id;
    cmd_init.channel_ring_id = test->channel_ring_id;
    cmd_init.channel_type = CROSS_DOMAIN_CHANNEL_TYPE_WAYLAND;

    cmd.ctx_id = test->ctx_id;
    cmd.cmd = (uint8_t *)&cmd_init;
    cmd.cmd_size = cmd_init.hdr.cmd_size;

    result = rutabaga_submit_command(test->rutabaga, &cmd);
    CHECK_RESULT(result);
    return 0;
}

static int test_command_submission(struct rutabaga_test *test)
{
    int result;
    struct CrossDomainGetImageRequirements cmd_get_reqs = { 0 };
    struct CrossDomainImageRequirements *image_reqs = (void *)test->query_iovecs[0].iov_base;
    struct rutabaga_create_blob rc_blob = { 0 };
    struct rutabaga_fence fence;
    struct rutabaga_handle handle = { 0 };
    struct rutabaga_command cmd = { 0 };
    uint32_t map_info;

    fence.flags = RUTABAGA_FLAG_FENCE | RUTABAGA_FLAG_INFO_RING_IDX;
    fence.ctx_id = test->ctx_id;
    fence.ring_idx = 0;

    cmd_get_reqs.hdr.cmd = CROSS_DOMAIN_CMD_GET_IMAGE_REQUIREMENTS;
    cmd_get_reqs.hdr.cmd_size = sizeof(struct CrossDomainGetImageRequirements);

    for (uint32_t i = 0; i < NUM_ITERATIONS; i++) {
        for (uint32_t j = 0; j < NUM_ITERATIONS; j++) {
            fence.fence_id = s_fence_id;
            map_info = 0;

            cmd_get_reqs.width = WIDTH * i;
            cmd_get_reqs.height = HEIGHT * j;
            cmd_get_reqs.drm_format = DRM_FORMAT_XRGB8888;

            cmd_get_reqs.flags = GBM_BO_USE_LINEAR | GBM_BO_USE_SCANOUT;

            cmd.ctx_id = test->ctx_id;
            cmd.cmd = (uint8_t *)&cmd_get_reqs;
            cmd.cmd_size = cmd_get_reqs.hdr.cmd_size;

            result = rutabaga_submit_command(test->rutabaga, &cmd);

            CHECK(test->value < fence.fence_id);
            result = rutabaga_create_fence(test->rutabaga, &fence);

            CHECK_RESULT(result);
            for (;;) {
                if (fence.fence_id == test->value)
                    break;
            }

            CHECK(image_reqs->strides[0] >= cmd_get_reqs.width * 4);
            CHECK(image_reqs->size >= (cmd_get_reqs.width * 4) * cmd_get_reqs.height);

            rc_blob.blob_mem = RUTABAGA_BLOB_MEM_HOST3D;
            rc_blob.blob_flags = RUTABAGA_BLOB_FLAG_USE_MAPPABLE | RUTABAGA_BLOB_FLAG_USE_SHAREABLE;
            rc_blob.blob_id = image_reqs->blob_id;
            rc_blob.size = image_reqs->size;

            result = rutabaga_resource_create_blob(test->rutabaga, test->ctx_id, s_resource_id,
                                                   &rc_blob, NULL, NULL);
            CHECK_RESULT(result);

            result = rutabaga_context_attach_resource(test->rutabaga, test->ctx_id, s_resource_id);
            CHECK_RESULT(result);

            result = rutabaga_resource_map_info(test->rutabaga, s_resource_id, &map_info);
            CHECK_RESULT(result);
            CHECK(map_info > 0);

            result = rutabaga_resource_export_blob(test->rutabaga, s_resource_id, &handle);
            CHECK_RESULT(result);
            CHECK(handle.os_handle >= 0);

            result = close(handle.os_handle);
            CHECK_RESULT(result);

            result = rutabaga_context_detach_resource(test->rutabaga, test->ctx_id, s_resource_id);
            CHECK_RESULT(result);

            result = rutabaga_resource_unref(test->rutabaga, s_resource_id);
            CHECK_RESULT(result);

            s_resource_id++;
            s_fence_id++;
        }
    }

    return 0;
}

static int test_context_finish(struct rutabaga_test *test)
{
    int result;

    result = rutabaga_context_detach_resource(test->rutabaga, test->ctx_id, test->query_ring_id);
    CHECK_RESULT(result);

    result = rutabaga_resource_unref(test->rutabaga, test->query_ring_id);
    CHECK_RESULT(result);

    free(test->query_iovecs[0].iov_base);

    result = rutabaga_context_detach_resource(test->rutabaga, test->ctx_id, test->channel_ring_id);
    CHECK_RESULT(result);

    result = rutabaga_resource_unref(test->rutabaga, test->channel_ring_id);
    CHECK_RESULT(result);

    free(test->channel_iovecs[0].iov_base);

    result = rutabaga_context_destroy(test->rutabaga, test->ctx_id);
    CHECK_RESULT(result);

    return 0;
}

static int test_rutabaga_2d(struct rutabaga_test *test)
{
    struct rutabaga_create_3d rc_3d = { 0 };
    struct rutabaga_transfer transfer = { 0 };
    int result;
    uint32_t resource_id = s_resource_id++;

    struct rutabaga_iovecs vecs = { 0 };
    struct iovec *iovecs = (struct iovec *)calloc(1, sizeof(struct iovec));
    uint8_t *test_data;
    struct iovec result_iovec;

    iovecs[0].iov_base = calloc(1, DEFAULT_BUFFER_SIZE);
    iovecs[0].iov_len = DEFAULT_BUFFER_SIZE;
    result_iovec.iov_base = calloc(1, DEFAULT_BUFFER_SIZE);
    result_iovec.iov_len = DEFAULT_BUFFER_SIZE;
    test_data = (uint8_t *)result_iovec.iov_base;

    vecs.iovecs = iovecs;
    vecs.num_iovecs = 1;

    rc_3d.target = PIPE_TEXTURE_2D;
    rc_3d.bind = PIPE_BIND_RENDER_TARGET;
    rc_3d.format = VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM;
    rc_3d.width = DEFAULT_BUFFER_SIZE / 16;
    rc_3d.height = 4;

    transfer.w = DEFAULT_BUFFER_SIZE / 16;
    transfer.h = 4;
    transfer.d = 1;

    result = rutabaga_resource_create_3d(test->rutabaga, resource_id, &rc_3d);
    CHECK_RESULT(result);

    result = rutabaga_resource_attach_backing(test->rutabaga, resource_id, &vecs);
    CHECK_RESULT(result);

    memset(iovecs[0].iov_base, 8, DEFAULT_BUFFER_SIZE);

    result =
        rutabaga_resource_transfer_read(test->rutabaga, 0, resource_id, &transfer, &result_iovec);
    CHECK_RESULT(result);

    CHECK(test_data[0] == 0);

    result = rutabaga_resource_transfer_write(test->rutabaga, 0, resource_id, &transfer);
    CHECK_RESULT(result);

    result =
        rutabaga_resource_transfer_read(test->rutabaga, 0, resource_id, &transfer, &result_iovec);
    CHECK_RESULT(result);

    CHECK(test_data[0] == 8);

    result = rutabaga_resource_detach_backing(test->rutabaga, resource_id);
    CHECK_RESULT(result);

    result = rutabaga_resource_unref(test->rutabaga, resource_id);
    CHECK_RESULT(result);

    free(iovecs[0].iov_base);
    free(iovecs);
    free(test_data);
    return 0;
}

static int test_rutabaga_finish(struct rutabaga_test *test)
{
    int result;

    result = rutabaga_finish(&test->rutabaga);
    CHECK_RESULT(result);
    CHECK(test->rutabaga == NULL);
    return 0;
}

int main(int argc, char *argv[])
{
    struct rutabaga_test test = { 0 };
    test.ctx_id = 1;
    test.query_ring_id = s_resource_id++;
    test.channel_ring_id = s_resource_id++;

    int result;

    const char *context_names[] = {
        NULL,
        "test_context",
    };
    const uint32_t num_context_names = 2;

    for (uint32_t i = 0; i < num_context_names; i++) {
        const char *context_name = context_names[i];
        for (uint32_t j = 0; j < NUM_ITERATIONS; j++) {
            result = test_capset_mask_calculation();
            CHECK_RESULT(result);

            result = test_rutabaga_init(&test, 1 << RUTABAGA_CAPSET_CROSS_DOMAIN);
            CHECK_RESULT(result);

            result |= test_create_context(&test, context_name);
            CHECK_RESULT(result);

            result |= test_init_context(&test);
            CHECK_RESULT(result);

            result |= test_command_submission(&test);
            CHECK_RESULT(result);

            result |= test_context_finish(&test);
            CHECK_RESULT(result);

            result |= test_rutabaga_finish(&test);
            CHECK_RESULT(result);
        }
    }

    for (uint32_t i = 0; i < NUM_ITERATIONS; i++) {
        result = test_rutabaga_init(&test, 0);
        CHECK_RESULT(result);

        result |= test_rutabaga_2d(&test);
        CHECK_RESULT(result);

        result |= test_rutabaga_finish(&test);
        CHECK_RESULT(result);
    }

    printf("[  PASSED  ] rutabaga_test success\n");
    return 0;
}

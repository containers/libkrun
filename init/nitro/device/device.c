// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "include/device.h"

int device_init(enum krun_nitro_device dev, int vsock_port, int shutdown_fd)
{
    int ret = 0;

    switch (dev) {
    case KRUN_NE_DEV_APP_OUTPUT_STDIO:
        ret = app_stdio_output(vsock_port);
        break;
    case KRUN_NE_DEV_NET_TAP_AF_VSOCK:
        ret = tap_afvsock_init(shutdown_fd, vsock_port);
        break;
    default:
        break;
    }

    return ret;
}

int device_exit(enum krun_nitro_device dev, int shutdown_fd)
{
    int ret;
    uint64_t sfd_val;

    ret = 0;

    switch (dev) {
    case KRUN_NE_DEV_APP_OUTPUT_STDIO:
        app_stdio_close();
        break;
    case KRUN_NE_DEV_NET_TAP_AF_VSOCK:
        sfd_val = 1;
        ret = write(shutdown_fd, &sfd_val, sizeof(uint64_t));
        if (ret < 0) {
            perror("write shutdown FD");
            ret = -errno;
        }
        break;
    default:
        break;
    }

    return ret;
}
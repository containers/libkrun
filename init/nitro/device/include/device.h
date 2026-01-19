// SPDX-License-Identifier: Apache-2.0

#ifndef _KRUN_NITRO_DEVICE_H
#define _KRUN_NITRO_DEVICE_H

enum krun_nitro_device {
    KRUN_NE_DEV_APP_OUTPUT_STDIO,
    KRUN_NE_DEV_NET_TAP_AF_VSOCK,
};

int device_init(enum krun_nitro_device, int, int);
int device_exit(enum krun_nitro_device, int);

int app_stdio_output(unsigned int);
void app_stdio_close(void);

int tap_afvsock_init(int, unsigned int);

#endif // _KRUN_NITRO_DEVICE_H

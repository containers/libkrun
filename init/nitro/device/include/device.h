// SPDX-License-Identifier: Apache-2.0

#ifndef _KRUN_NITRO_DEVICE_H
#define _KRUN_NITRO_DEVICE_H

#include <signal.h>

/*
 * Variable for device proxies to indicate to the main process that they have
 * finished initialization.
 */
static volatile sig_atomic_t DEVICE_PROXY_READY = 0;

/*
 * Device proxy signal handler. Used by device proxy processes to notify the
 * main process that they have finished initialization.
 */
void device_proxy_sig_handler(int);

enum krun_nitro_device {
    KRUN_NE_DEV_SIGNAL_HANDLER,
    KRUN_NE_DEV_APP_OUTPUT_STDIO,
    KRUN_NE_DEV_NET_TAP_AF_VSOCK,
};

int device_init(enum krun_nitro_device, int, int);

int sig_handler_init(unsigned int, int);

int app_stdio_output(unsigned int);
void app_stdio_close(void);

int tap_afvsock_init(unsigned int, int);

#endif // _KRUN_NITRO_DEVICE_H

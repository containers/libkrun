// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "include/device.h"

/*
 * Upon receiving SIGUSR1 from a device proxy process, set the proxy ready
 * variable to indicate the proxy is finished initializing and the main process
 * can continue.
 */
void device_proxy_sig_handler(int sig)
{
    if (sig == SIGUSR1)
        DEVICE_PROXY_READY = 1;
}

/*
 * Initialize a specific device proxy.
 */
int device_init(enum krun_nitro_device dev, int vsock_port, int shutdown_fd)
{
    int ret;

    ret = 0;
    DEVICE_PROXY_READY = 0;

    switch (dev) {
    /*
     * Some proxies will fork to produce separate processes. These processes
     * will send a signal to the main process to indicate when they have
     * finished initialization. When applicable, the main process must wait for
     * this signal before continuing execution.
     */
    case KRUN_NE_DEV_SIGNAL_HANDLER:
        ret = sig_handler_init(vsock_port, shutdown_fd);
        while (!DEVICE_PROXY_READY)
            ;
        break;
    case KRUN_NE_DEV_APP_OUTPUT_STDIO:
        ret = app_stdio_output(vsock_port);
        break;
    case KRUN_NE_DEV_NET_TAP_AF_VSOCK:
        ret = tap_afvsock_init(vsock_port, shutdown_fd);
        while (!DEVICE_PROXY_READY)
            ;
        break;
    }

    return ret;
}
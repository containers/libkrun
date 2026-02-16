// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "include/device.h"

static int APP_STDIO_OUTPUT_VSOCK_FD = -1;

/*
 * Redirect std{err, out} output to a vsock connected to the host. Allows the
 * host to read application output.
 */
int app_stdio_output(unsigned int vsock_port)
{
    int streams[2] = {STDOUT_FILENO, STDERR_FILENO};
    struct sockaddr_vm addr;
    struct timeval timeval;
    int ret, sock_fd, i;

    // Open a vsock and connect to the host.
    sock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("unable to create guest socket");
        return -errno;
    }

    bzero((char *)&addr, sizeof(struct sockaddr_vm));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_HOST;
    addr.svm_port = vsock_port;

    memset(&timeval, 0, sizeof(struct timeval));
    timeval.tv_sec = 5;

    ret = setsockopt(sock_fd, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
                     (void *)&timeval, sizeof(struct timeval));
    if (ret < 0) {
        perror("unable to set application output vsock timeout");
        close(sock_fd);
        return -errno;
    }

    ret = connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("unable to connect to host socket");
        close(sock_fd);
        return -errno;
    }

    // Refer the std{err, out} file descriptors to the connected vsock.
    for (i = 0; i < 2; i++) {
        ret = dup2(sock_fd, streams[i]);
        if (ret < 0) {
            fprintf(stderr, "unable to redirect stream [%d] to socket: %s\n",
                    streams[i], strerror(errno));
            close(sock_fd);
            return -errno;
        }
    }

    // Store the vsock's file descriptor for eventual closing.
    APP_STDIO_OUTPUT_VSOCK_FD = sock_fd;

    return 0;
}

/*
 * Dereference and close the application output vsock.
 */
void app_stdio_close(void)
{
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    if (APP_STDIO_OUTPUT_VSOCK_FD >= 0) {
        close(APP_STDIO_OUTPUT_VSOCK_FD);
        APP_STDIO_OUTPUT_VSOCK_FD = -1;
    }
}

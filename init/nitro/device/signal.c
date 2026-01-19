// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>

#include <linux/vm_sockets.h>

#include "include/device.h"

static int sig_handler_start(int vsock_fd, int shutdown_fd)
{
    struct pollfd pfds[2];
    ssize_t len;
    int sig;

    pfds[0].fd = vsock_fd;
    pfds[0].events = POLLIN;

    pfds[1].fd = shutdown_fd;
    pfds[1].events = POLLIN;

    kill(getppid(), SIGUSR1);

    while (poll(pfds, 2, -1) > 0) {
        if (pfds[0].revents & POLLIN) {
            len = read(vsock_fd, (void *)&sig, sizeof(int));
            if (len != sizeof(int)) {
                sig = SIGTERM;
            }

            kill(getppid(), sig);
        }

        if (pfds[1].revents & POLLIN)
            break;
    }

    close(vsock_fd);

    exit(0);
}

int sig_handler_init(unsigned int vsock_port, int shutdown_fd)
{
    struct sockaddr_vm saddr;
    struct timeval timeval;
    int ret, vsock_fd;
    pid_t pid;

    pid = fork();
    switch (pid) {
    case -1:
        perror("signal handler proxy process");
        return -errno;
    case 0:
        vsock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        if (vsock_fd < 0) {
            perror("signal handler vsock creation");
            return -errno;
        }

        memset(&timeval, 0, sizeof(struct timeval));
        timeval.tv_sec = 5;
        ret = setsockopt(vsock_fd, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
                         (void *)&timeval, sizeof(struct timeval));
        if (ret < 0) {
            perror("set signal handler proxy socket connect timeout");
            close(vsock_fd);
            return -errno;
        }

        memset(&saddr, 0, sizeof(struct sockaddr_vm));
        saddr.svm_family = AF_VSOCK;
        saddr.svm_cid = VMADDR_CID_HOST;
        saddr.svm_port = vsock_port;
        saddr.svm_reserved1 = 0;

        ret = connect(vsock_fd, (struct sockaddr *)&saddr, sizeof(saddr));
        if (ret < 0) {
            perror("signal handler vsock connect");
            close(vsock_fd);
            return -errno;
        }

        ret = sig_handler_start(vsock_fd, shutdown_fd);
        if (ret < 0) {
            close(vsock_fd);
            return ret;
        }

        return 0;
    }
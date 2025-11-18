// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include <linux/vm_sockets.h>

#include "include/vsock.h"

#define UINT64_T_SIZE 8

#define HEART_BEAT 0xb7
#define VSOCK_CID 3
#define VSOCK_PORT 9000

static int vsock_len_read(int sock_fd, uint32_t *size)
{
    uint8_t bytes[UINT64_T_SIZE];
    ssize_t ret;

    ret = read(sock_fd, bytes, UINT64_T_SIZE);
    if (ret < UINT64_T_SIZE) {
        perror("vsock byte buffer length read");
        return -errno;
    }

    memcpy(size, bytes, sizeof(uint32_t));

    return 0;
}

void char_list_free(char **buf)
{
    char *ptr;

    for (int i = 0; (ptr = buf[i]) != NULL; ++i)
        free((void *)ptr);

    free((void *)buf);
}

int vsock_char_list_build(int sock_fd, char ***buf_ptr)
{
    uint32_t size;
    char **buf;
    int ret, i;

    size = 0;
    ret = vsock_len_read(sock_fd, &size);
    if (ret < 0)
        return ret;

    // Allocate extra space for NULL-terminator.
    buf = (char **)malloc(sizeof(char *) * (size + 1));
    if (buf == NULL) {
        perror("vsock char list buffer malloc");
        return -errno;
    }

    for (i = 0; i < size; ++i) {
        ret = vsock_rcv(sock_fd, (void **)&buf[i], NULL);
        if (ret < 0) {
            char_list_free(buf);
            return ret;
        }
    }

    buf[i] = NULL;

    *buf_ptr = buf;

    return 0;
}

int vsock_rcv(int sock_fd, void **buf_ptr, uint32_t *size)
{
    uint32_t len, idx;
    ssize_t read_len;
    uint8_t *buf;
    int ret;

    len = idx = 0;

    ret = vsock_len_read(sock_fd, &len);
    if (ret < 0)
        return ret;

    if (size != NULL)
        *size = len;

    buf = (uint8_t *)malloc(sizeof(uint8_t) * len);
    if (buf == NULL) {
        perror("vsock byte buffer malloc");
        return -errno;
    }

    while (len) {
        read_len = read(sock_fd, &buf[idx], len);
        if (read_len <= 0) {
            free((void *)buf);
            perror("vsock byte buffer read");
            return -errno;
        }
        idx += read_len;
        len -= read_len;
    }

    *buf_ptr = (void *)buf;

    return 0;
}

/*
 * Signal to the host that the enclave is ready to receive the archived rootfs.
 */
int vsock_hypervisor_signal()
{
    uint8_t buf[1];
    struct sockaddr_vm saddr;
    int ret, sock_fd;

    buf[0] = HEART_BEAT;
    errno = -EINVAL;

    saddr.svm_family = AF_VSOCK;
    saddr.svm_cid = VSOCK_CID;
    saddr.svm_port = VSOCK_PORT;
    saddr.svm_reserved1 = 0;

    sock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("vsock initialization");
        return -errno;
    }

    // Connect to the host.
    ret = connect(sock_fd, (struct sockaddr *)&saddr, sizeof(saddr));
    if (ret < 0) {
        perror("vsock connect");
        goto err;
    }

    // Write the heartbeat to the host and read it back to ensure that the
    // communication is established.
    ret = write(sock_fd, buf, 1);
    if (ret != 1) {
        perror("vsock write");
        goto err;
    }

    ret = read(sock_fd, buf, 1);
    if (ret != 1) {
        perror("vsock read");
        goto err;
    }

    if (buf[0] != HEART_BEAT) {
        printf("unable to establish connection to hypervisor\n");
        errno = 1;
        goto err;
    }

    return sock_fd;

err:
    close(sock_fd);
    return -errno;
}

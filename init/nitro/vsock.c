// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "include/vsock.h"

#define UINT64_T_SIZE 8

static int
vsock_len_read(int sock_fd, uint32_t *size)
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

int
vsock_char_list_build(int sock_fd, char ***buf_ptr)
{
    uint32_t size;
    char **buf;
    int ret, i;

    size = 0;
    ret = vsock_len_read(sock_fd, &size);
    if (ret < 0)
        return ret;

    // Allocate extra space for NULL-terminator.
    buf = (char **) malloc(sizeof(char *) * (size + 1));
    if (buf == NULL) {
        perror("vsock char list buffer malloc");
        return -errno;
    }

    for (i = 0; i < size; ++i) {
        ret = vsock_rcv(sock_fd, (void **) &buf[i], NULL);
        if (ret < 0) {
            free((void *) buf);
            return ret;
        }
    }

    buf[i] = NULL;

    *buf_ptr = buf;

    return 0;
}

int
vsock_rcv(int sock_fd, void **buf_ptr, uint32_t *size)
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

    buf = (uint8_t *) malloc(sizeof(uint8_t) * len);
    if (buf == NULL) {
        perror("vsock byte buffer malloc");
        return -errno;
    }

    while (len) {
        read_len = read(sock_fd, &buf[idx], len);
        if (read_len <= 0) {
            free((void *) buf);
            perror("vsock byte buffer read");
            return -errno;
        }
        idx += read_len;
        len -= read_len;
    }

    *buf_ptr = (void *) buf;

    return 0;
}

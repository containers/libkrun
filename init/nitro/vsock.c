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

#define UINT32_T_SIZE 4

#define HEART_BEAT 0xb7
#define VSOCK_CID 3
#define VSOCK_PORT 9000

/*
 * Before reading data from the vsock, the vsock sends a 4-byte "header",
 * representing the size (in bytes) of the object that will be written over the
 * stream. Read this size and store it within a uint32_t variable.
 */
static int vsock_len_read(int sock_fd, uint32_t *size)
{
    uint8_t bytes[UINT32_T_SIZE];
    ssize_t ret;

    // Read the bytes (representing the size) from the vsock.
    ret = read(sock_fd, bytes, UINT32_T_SIZE);
    if (ret < UINT32_T_SIZE) {
        perror("vsock byte buffer length read");
        return -errno;
    }

    // Store the size within the "size" argument.
    memcpy(size, bytes, sizeof(uint32_t));

    return 0;
}

/*
 * Free each string in an array, then free the array pointer itself.
 */
void char_list_free(char **buf)
{
    char *ptr;

    for (int i = 0; (ptr = buf[i]) != NULL; ++i)
        free((void *)ptr);

    free((void *)buf);
}

/*
 * Build an array of strings read from the vsock.
 */
int vsock_char_list_build(int sock_fd, char ***buf_ptr)
{
    uint32_t size;
    char **buf;
    int ret, i;

    // Read the size of the string array.
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

    // Read each string in the array, storing them at each index.
    for (i = 0; i < size; ++i) {
        ret = vsock_rcv(sock_fd, (void **)&buf[i], NULL);
        if (ret < 0) {
            char_list_free(buf);
            return ret;
        }
    }

    // NULL-terminate the array.
    buf[i] = NULL;

    *buf_ptr = buf;

    return 0;
}

/*
 * Read and store an object from the vsock stream.
 */
int vsock_rcv(int sock_fd, void **buf_ptr, uint32_t *size)
{
    uint32_t len, idx;
    ssize_t read_len;
    uint8_t *buf;
    int ret;

    len = idx = 0;

    // Read the length of the object.
    ret = vsock_len_read(sock_fd, &len);
    if (ret < 0)
        return ret;

    if (size != NULL)
        *size = len;

    /*
     * Allocate a buffer to store the object based on the size read from the
     * hypervisor.
     */
    buf = (uint8_t *)malloc(sizeof(uint8_t) * len);
    if (buf == NULL) {
        perror("vsock byte buffer malloc");
        return -errno;
    }

    // Read the object from the vsock.
    while (len) {
        read_len = read(sock_fd, &buf[idx], len);
        if (read_len <= 0) {
            free((void *)buf);
            perror("vsock byte buffer read");
            return -errno;
        }

        /*
         * In case the buffer was not fully written, update the write index
         * within the buffer (to prevent overwriting upon the next read from the
         * vsock) and amount of data (in bytes) that are still needed to be
         * read.
         */
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

    /*
     * Read a byte from the host (and ensure it is the same value that was
     * written) to ensure the hypervisor has also established communication.
     */
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

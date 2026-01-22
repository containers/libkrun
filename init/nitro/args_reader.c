// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include <linux/vm_sockets.h>

#include "include/args_reader.h"

#define ENCLAVE_VSOCK_LAUNCH_ARGS_READY 0xb7

enum {
    ENCLAVE_ARG_ID_ROOTFS,
    ENCLAVE_ARG_ID_EXEC_PATH,
    ENCLAVE_ARG_ID_EXEC_ARGV,
    ENCLAVE_ARG_ID_EXEC_ENVP,
    ENCLAVE_ARG_ID_NETWORK_PROXY,
    ENCLAVE_ARG_ID_DEBUG,

    ENCLAVE_ARGS_FINISHED = 255,
};

/*
 * Before reading data from the vsock, the vsock sends a 4-byte "header",
 * representing the size (in bytes) of the object that will be written over the
 * stream. Read this size and store it within a uint64_t variable.
 */
static int args_reader_len_read(int sock_fd, uint64_t *size)
{
    uint8_t bytes[sizeof(uint64_t)];
    ssize_t ret;

    // Read the bytes (representing the size) from the vsock.
    ret = read(sock_fd, bytes, sizeof(uint64_t));
    if (ret < sizeof(uint64_t)) {
        perror("vsock byte buffer length read");
        return -errno;
    }

    // Store the size within the "size" argument.
    memcpy(size, bytes, sizeof(uint64_t));

    return 0;
}

/*
 * Free each string in an array, then free the array pointer itself.
 */
static void char_list_free(char **buf)
{
    char *ptr;

    for (int i = 0; (ptr = buf[i]) != NULL; ++i)
        free((void *)ptr);

    free((void *)buf);
}

/*
 * Read and store an object from the vsock stream.
 */
static int args_reader_rcv(int sock_fd, void **buf_ptr, uint64_t *size)
{
    uint64_t len, idx;
    ssize_t read_len;
    uint8_t *buf;
    int ret;

    len = idx = 0;

    // Read the length of the object.
    ret = args_reader_len_read(sock_fd, &len);
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
 * Build an array of strings read from the vsock.
 */
static int args_reader_char_list_build(int sock_fd, char ***buf_ptr)
{
    uint64_t size;
    char **buf;
    int ret, i;

    // Read the size of the string array.
    size = 0;
    ret = args_reader_len_read(sock_fd, &size);
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
        ret = args_reader_rcv(sock_fd, (void **)&buf[i], NULL);
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
 * Signal to the host that the enclave is ready to receive the enclave
 * arguments.
 */
static int args_reader_signal(unsigned int vsock_port)
{
    uint8_t buf[1];
    struct sockaddr_vm saddr;
    int ret, sock_fd;

    buf[0] = ENCLAVE_VSOCK_LAUNCH_ARGS_READY;
    errno = -EINVAL;

    saddr.svm_family = AF_VSOCK;
    saddr.svm_cid = VMADDR_CID_HOST;
    saddr.svm_port = vsock_port;
    saddr.svm_reserved1 = 0;

    sock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("arguments reader initialization");
        return -errno;
    }

    // Connect to the host.
    ret = connect(sock_fd, (struct sockaddr *)&saddr, sizeof(saddr));
    if (ret < 0) {
        perror("arguments reader connect");
        goto err;
    }

    // Write the heartbeat to the host and read it back to ensure that the
    // communication is established.
    ret = write(sock_fd, buf, 1);
    if (ret != 1) {
        perror("arguments reader write");
        goto err;
    }

    /*
     * Read a byte from the host (and ensure it is the same value that was
     * written) to ensure the hypervisor has also established communication.
     */
    ret = read(sock_fd, buf, 1);
    if (ret != 1) {
        perror("arguments reader read");
        goto err;
    }

    if (buf[0] != ENCLAVE_VSOCK_LAUNCH_ARGS_READY) {
        printf("unable to establish connection to hypervisor\n");
        errno = 1;
        goto err;
    }

    return sock_fd;

err:
    close(sock_fd);
    return -errno;
}

static int __args_reader_read(int sock_fd, struct enclave_args *args)
{
    uint8_t id;
    int ret;

    for (;;) {
        // Read the argument identifier.
        ret = read(sock_fd, &id, sizeof(uint8_t));
        if (ret < 0) {
            perror("arguments reader read argument ID");
            return -errno;
        }

        // Read the argument according to the identifier.
        switch (id) {
        case ENCLAVE_ARG_ID_ROOTFS:
            ret = args_reader_rcv(sock_fd, &args->rootfs_archive,
                                  &args->rootfs_archive_size);
            break;
        case ENCLAVE_ARG_ID_EXEC_PATH:
            ret = args_reader_rcv(sock_fd, (void **)&args->exec_path, NULL);
            break;
        case ENCLAVE_ARG_ID_EXEC_ARGV:
            ret = args_reader_char_list_build(sock_fd, &args->exec_argv);
            break;
        case ENCLAVE_ARG_ID_EXEC_ENVP:
            ret = args_reader_char_list_build(sock_fd, &args->exec_envp);
            break;
        case ENCLAVE_ARG_ID_NETWORK_PROXY:
            args->network_proxy = true;
            break;
        case ENCLAVE_ARG_ID_DEBUG:
            args->debug = true;
            break;

        /*
         * End of enclave arguments, return from the function with the
         * parsed arguments.
         */
        case ENCLAVE_ARGS_FINISHED:
            return 0;
        }

        if (ret < 0)
            return ret;
    }
}

int args_reader_read(struct enclave_args *args, unsigned int vsock_port)
{
    int ret, sock_fd;

    /*
     * Open the arguments reader and signal to the hypervisor that the enclave
     * is booted and ready to read the arguments.
     */
    sock_fd = args_reader_signal(vsock_port);
    if (sock_fd < 0)
        return sock_fd;

    // Read the arguments.
    ret = __args_reader_read(sock_fd, args);
    if (ret < 0) {
        close(sock_fd);
        return ret;
    }

    // Communication with the hypervisor is complete, close the argument reader.
    close(sock_fd);

    return 0;
}

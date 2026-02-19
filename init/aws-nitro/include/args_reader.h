// SPDX-License-Identifier: Apache-2.0

#ifndef _KRUN_NITRO_ARGS_READER_H
#define _KRUN_NITRO_ARGS_READER_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Enclave configuration arguments written from the host.
 */
struct enclave_args {
    void *rootfs_archive;         // rootfs tar archive.
    uint64_t rootfs_archive_size; // Size of rootfs tar archive.
    char *exec_path;              // Path of execution binary.
    char **exec_argv;             // Execution argument vector.
    char **exec_envp;             // Execution environment pointer.
    bool network_proxy;           // Indicate if networking is configured.
    bool app_output;              // Indicate if running in non-debug mode.
};

int args_reader_read(struct enclave_args *, unsigned int);

#endif // _KRUN_NITRO_ARGS_READER_H

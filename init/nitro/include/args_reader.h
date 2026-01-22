// SPDX-License-Identifier: Apache-2.0

#ifndef _KRUN_NITRO_ARGS_READER_H
#define _KRUN_NITRO_ARGS_READER_H

#include <stdbool.h>
#include <stdint.h>

struct enclave_args {
    void *rootfs_archive;
    uint64_t rootfs_archive_size;
    char *exec_path;
    char **exec_argv;
    char **exec_envp;
    bool network_proxy;
    bool debug;
};

int args_reader_read(struct enclave_args *, unsigned int);

#endif // _KRUN_NITRO_ARGS_READER_H

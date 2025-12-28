// SPDX-License-Identifier: Apache-2.0

#ifndef _KRUN_NITRO_INIT_ARGS_READER_H
#define _KRUN_NITRO_INIT_ARGS_READER_H

#include <stdbool.h>
#include <stdint.h>

struct enclave_args {
    void *rootfs_archive;
    uint32_t rootfs_archive_size;
    char *exec_path;
    char **exec_argv;
    char **exec_envp;
    bool network_proxy;
};

int args_reader_read(struct enclave_args *);

#endif // _KRUN_NITRO_INIT_ARGS_READER_H

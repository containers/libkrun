// SPDX-License-Identifier: Apache-2.0

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "include/mod.h"

#define KRUN_LINUX_MODS_DIR_NAME "/krun_linux_mods"
#define MOD_FILE_NAME_BUF_SIZE 256

#define finit_module(fd, param_values, flags)                                  \
    (int)syscall(__NR_finit_module, fd, param_values, flags)

/*
 * Load a kernel module.
 */
static int mod_load(const char *path)
{
    int fd, ret;

    // Open and load the kernel module.
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT)
            return 0;

        fprintf(stderr, "open module %s (errno %d)\n", path, errno);
        return -errno;
    }

    ret = finit_module(fd, "", 0);
    if (ret < 0) {
        close(fd);
        fprintf(stderr, "init module %s (errno %d)\n", path, errno);
        return -errno;
    }

    // Close the file descriptor and remove the module file.
    ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "close module %s (errno %d)\n", path, errno);
        return -errno;
    }

    ret = unlink(path);
    if (ret < 0) {
        fprintf(stderr, "unlink module %s (errno %d)\n", path, errno);
        return -errno;
    }

    return 0;
}

/*
 * Load the configured kernel modules.
 */
int mods_load(void)
{
    char path[MOD_FILE_NAME_BUF_SIZE + sizeof(KRUN_LINUX_MODS_DIR_NAME) + 1];
    struct dirent *entry;
    int ret;
    DIR *dir;

    ret = 0;

    dir = opendir(KRUN_LINUX_MODS_DIR_NAME);
    if (dir != NULL) {
        while ((entry = readdir(dir)) != NULL) {
            /*
             * Ignore the "." and ".." directory entries, as they are not kernel
             * modules.
             */
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;

            // Copy the full path of the module file.
            snprintf(path, sizeof(path), "%s/%s", KRUN_LINUX_MODS_DIR_NAME,
                     entry->d_name);
            ret = mod_load(path);
            if (ret < 0)
                break;
        }
        closedir(dir);
    } else if (errno != ENOENT) {
        ret = -errno;
        perror("unable to open kernel module configuration directory");
    }

    return ret;
}

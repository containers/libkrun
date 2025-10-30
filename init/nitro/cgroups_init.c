// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "include/cgroups_init.h"

int
cgroups_init()
{
    const char *fpath = "/proc/cgroups";
    int ret, heir, groups, enabled;
    FILE *f;

    f = fopen(fpath, "r");
    if (f == NULL) {
        perror("fopen /proc/cgroups");
        return -errno;
    }

    // Skip the first line.
    do {
        ret = fgetc(f);
    } while (ret != EOF && ret != '\n');

    for (;;) {
        static const char base_path[] = "/sys/fs/cgroup/";
        char path[sizeof(base_path) - 1 + 64];
        char *name = path + sizeof(base_path) - 1;
        ret = fscanf(f, "%64s %d %d %d\n", name, &heir, &groups, &enabled);
        if (ret == EOF)
            break;

        if (ret != 4) {
            fclose(f);
            errno = errno ? : EINVAL;
            perror("fscan /sys/fs/cgroup");
            return -errno;
        }

        if (enabled) {
            memcpy(path, base_path, sizeof(base_path) - 1);

            ret = mkdir(path, 0755);
            if (ret < 0) {
                fclose(f);
                perror("mkdir cgroup path");
                return -errno;
            }

            ret = mount(name, path, "cgroup", MS_NODEV | MS_NOSUID | MS_NOEXEC,
                        name);
            if (ret < 0) {
                fclose(f);
                perror("mount cgroup");
                return -errno;
            }
        }
    }

    fclose(f);

    return 0;
}

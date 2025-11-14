// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "include/fs.h"

int cgroups_init()
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
            errno = errno ?: EINVAL;
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

int filesystem_init()
{
    int ret;

    ret =
        mount("proc", "/proc", "proc", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < 0) {
        perror("mount /proc");
        return -errno;
    }

    ret = symlink("/proc/self/fd", "/dev/fd");
    if (ret < 0) {
        perror("symlink add");
        return -errno;
    }

    ret = symlink("/proc/self/fd/0", "/dev/stdin");
    if (ret < 0) {
        perror("symlink add");
        return -errno;
    }

    ret = symlink("/proc/self/fd/1", "/dev/stdout");
    if (ret < 0) {
        perror("symlink add");
        return -errno;
    }

    ret = symlink("/proc/self/fd/2", "/dev/stderr");
    if (ret < 0) {
        perror("symlink add");
        return -errno;
    }

    ret = mount("tmpfs", "/run", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC,
                "mode=0755");
    if (ret < 0) {
        perror("mount /run");
        return -errno;
    }

    ret =
        mount("tmpfs", "/tmp", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < 0) {
        perror("mount /tmp");
        return -errno;
    }

    ret = mkdir("/dev/shm", 0755);
    if (ret < 0) {
        perror("mkdir /dev/shm");
        return -errno;
    }

    ret = mount("shm", "/dev/shm", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC,
                NULL);
    if (ret < 0) {
        perror("mount /dev/shm");
        return -errno;
    }

    ret = mkdir("/dev/pts", 0755);
    if (ret < 0) {
        perror("mkdir /dev/pts");
        return -errno;
    }

    ret = mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < 0) {
        perror("mount /dev/pts");
        return -errno;
    }

    ret =
        mount("sysfs", "/sys", "sysfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < 0) {
        perror("mount /sys");
        return -errno;
    }

    ret = mount("cgroup_root", "/sys/fs/cgroup", "tmpfs",
                MS_NODEV | MS_NOSUID | MS_NOEXEC, "mode=0755");
    if (ret < 0) {
        perror("mount /sys/fs/cgroup");
        return -errno;
    }

    return 0;
}

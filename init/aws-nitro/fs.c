// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "include/fs.h"

#define PROC_CGROUPS_PATH "/proc/cgroups"
#define SYS_FS_CGROUP_PATH "/sys/fs/cgroup/"
#define CGROUP_SUB_PATH_SIZE (sizeof(SYS_FS_CGROUP_PATH) - 1 + 64)

#define NUM_SYS_DIRS 5
#define NUM_DEV_DIRS 2

/*
 * Initialize /dev/console and redirect std{err, in, out} to it for early debug
 * output.
 */
int console_init(void)
{
    const char *path = "/dev/console";
    FILE *file;
    int ret;

    ret = mount("dev", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < 0 && errno != EBUSY) {
        perror("mount /dev");
        return -errno;
    }

    // Redirect stdin, stdout, and stderr to /dev/console.
    file = freopen(path, "r", stdin);
    if (file == NULL) {
        perror("freopen stdin");
        return -errno;
    }

    file = freopen(path, "w", stdout);
    if (file == NULL) {
        perror("freopen stdout");
        goto err;
    }

    file = freopen(path, "w", stderr);
    if (file == NULL) {
        perror("freopen stderr");
        goto err;
    }

    return 0;

err:
    fclose(file);
    return -errno;
}

/*
 * Initialize the cgroups.
 */
int cgroups_init(void)
{
    char path[CGROUP_SUB_PATH_SIZE], *name;
    int ret, heir, groups, enabled;
    FILE *f;

    f = fopen(PROC_CGROUPS_PATH, "r");
    if (f == NULL) {
        perror("fopen /proc/cgroups");
        return -errno;
    }

    // Skip the first line.
    do {
        ret = fgetc(f);
    } while (ret != EOF && ret != '\n');

    for (;;) {
        name = path + sizeof(SYS_FS_CGROUP_PATH) - 1;

        ret = fscanf(f, "%64s %d %d %d\n", name, &heir, &groups, &enabled);
        if (ret == EOF)
            break;

        if (ret != 4) {
            errno = errno ?: EINVAL;
            perror("fscan /sys/fs/cgroup");
            goto err;
        }

        if (enabled) {
            memcpy(path, SYS_FS_CGROUP_PATH, sizeof(SYS_FS_CGROUP_PATH) - 1);

            ret = mkdir(path, 0755);
            if (ret < 0) {
                perror("mkdir cgroup path");
                goto err;
            }

            ret = mount(name, path, "cgroup", MS_NODEV | MS_NOSUID | MS_NOEXEC,
                        name);
            if (ret < 0) {
                perror("mount cgroup");
                goto err;
            }
        }
    }

    ret = 0;
    goto out;

err:
    ret = -errno;

out:
    fclose(f);
    return ret;
}

/*
 * Initialize the rest of the root filesystem with ephemeral enclave file
 * systems.
 */
int filesystem_init(void)
{
    char *sys_dirs[NUM_SYS_DIRS] = {"/dev", "/proc", "/run", "/sys", "/tmp"},
         *dir;
    char *dev_dirs[NUM_DEV_DIRS] = {"/dev/shm", "/dev/pts"};
    int ret, i;

    // Create the system directories not provided by the enclave rootfs.
    for (i = 0; i < NUM_SYS_DIRS; i++) {
        dir = sys_dirs[i];

        ret = mkdir(dir, 0755);
        if (ret < 0) {
            fprintf(stderr, "mkdir %s: %s\n", dir, strerror(errno));
            return -errno;
        }
    }

    // Mount the /dev file system for device files.
    ret = mount("/dev", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < -1 && errno != EBUSY) {
        perror("mount /dev");
        return -errno;
    }

    // Create the initial device files.
    for (i = 0; i < NUM_DEV_DIRS; i++) {
        dir = dev_dirs[i];

        ret = mkdir(dir, 0755);
        if (ret < 0) {
            fprintf(stderr, "mkdir %s: %s\n", dir, strerror(errno));
            return -errno;
        }
    }

    ret = mount("shm", "/dev/shm", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC,
                NULL);
    if (ret < 0) {
        perror("mount /dev/shm");
        return -errno;
    }

    ret = mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < 0) {
        perror("mount /dev/pts");
        return -errno;
    }

    /*
     * Initialize the /proc file system for special files representing the
     * current state of the kernel.
     */
    ret =
        mount("/proc", "/proc", "proc", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL);
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
        perror("symlink add /dev/stdin");
        return -errno;
    }

    ret = symlink("/proc/self/fd/1", "/dev/stdout");
    if (ret < 0) {
        perror("symlink add /dev/stdout");
        return -errno;
    }

    ret = symlink("/proc/self/fd/2", "/dev/stderr");
    if (ret < 0) {
        perror("symlink add /dev/stderr");
        return -errno;
    }

    /*
     * Mount the /run directory to store volatile runtime data about the system
     * since boot.
     */
    ret = mount("tmpfs", "/run", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC,
                "mode=0755");
    if (ret < 0) {
        perror("mount /run");
        return -errno;
    }

    /*
     * Mount the /tmp directory for temporary files (cleared on reboot).
     */
    ret =
        mount("tmpfs", "/tmp", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < 0) {
        perror("mount /tmp");
        return -errno;
    }

    /*
     * Mount the sysfs, accessed to set or obtain information about the kernel's
     * view of the system.
     */
    ret =
        mount("sysfs", "/sys", "sysfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < 0) {
        perror("mount /sys");
        return -errno;
    }

    // Initialize the cgroup root.
    ret = mount("cgroup_root", "/sys/fs/cgroup", "tmpfs",
                MS_NODEV | MS_NOSUID | MS_NOEXEC, "mode=0755");
    if (ret < 0) {
        perror("mount /sys/fs/cgroup");
        return -errno;
    }

    return 0;
}

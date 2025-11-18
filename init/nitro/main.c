// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <nsm.h>

#include "include/archive.h"
#include "include/fs.h"
#include "include/vsock.h"

#define finit_module(fd, param_values, flags)                                  \
    (int)syscall(__NR_finit_module, fd, param_values, flags)

#define NSM_PCR_ROOTFS 16
#define NSM_PCR_EXEC_DATA 17

#define NSM_PCR_CHUNK_SIZE 0x800 // 2 KiB.

/*
 * Block or unblock signals.
 *
 * NOTE: All signals are blocked before the devies or console are set up.
 *       Therefore, perror output may not be displayed if a failure occurs
 *       during this setup.
 */
int sig_mask(int mask)
{
    sigset_t set;
    int ret;

    // Initialize the signal set to the complete set of supported signals.
    ret = sigfillset(&set);
    if (ret < 0) {
        perror("sigfillset");
        return ret;
    }

    // Block/unblock the signals. This essentially blocks/unblocks all signals
    // to the process.
    ret = sigprocmask(mask, &set, 0);
    if (ret < 0) {
        perror("sigprocmask");
        return ret;
    }

    return 0;
}

/*
 * Initialize /dev/console and redirect std{err, in, out} to it for early debug
 * output.
 */
int console_init()
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
        return -errno;
    }

    file = freopen(path, "w", stderr);
    if (file == NULL) {
        perror("freopen stderr");
        return -errno;
    }

    return 0;
}

/*
 * Initialize/load the NSM kernel module.
 */
int nsm_init()
{
    const char *file_name = "nsm.ko";
    int fd, ret;

    fd = open(file_name, O_RDONLY | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT)
        return 0;
    else if (fd < 0) {
        perror("nsm.ko open");
        return -errno;
    }

    // Load the NSM module.
    ret = finit_module(fd, "", 0);
    if (ret < 0) {
        close(fd);
        perror("nsm.ko finit_module");
        return -errno;
    }

    // Close the file descriptor and remove the NSM module file.
    ret = close(fd);
    if (ret < 0) {
        perror("nsm.ko close");
        return -errno;
    }

    ret = unlink(file_name);
    if (ret < 0) {
        perror("nsm.ko unlink");
        return -errno;
    }

    return 0;
}

static int rootfs_mount()
{
    int ret;

    // Mount /rootfs.
    ret = mount("/rootfs", "/rootfs", NULL, MS_BIND, NULL);
    if (ret < 0) {
        perror("rootfs mount");
        return -errno;
    }

    // Change directory to rootfs.
    ret = chdir("/rootfs");
    if (ret < 0) {
        perror("rootfs chdir");
        return -errno;
    }

    // Mount the current directory (/rootfs) on the system root.
    ret = mount(".", "/", NULL, MS_MOVE, NULL);
    if (ret < 0) {
        perror("rootfs system root mount");
        return -errno;
    }

    // Change the system root.
    ret = chroot(".");
    if (ret < 0) {
        perror("rootfs chroot");
        return -errno;
    }

    // Change the directory to the new root (originally /rootfs).
    ret = chdir("/");
    if (ret < 0) {
        perror("rootfs chdir \"/\"");
        return -errno;
    }

    return 0;
}

pid_t launch(char **argv, char **envp)
{
    int ret, pid;

    pid = fork();
    if (pid < 0) {
        perror("launch fork");
        return -errno;
    } else if (pid != 0) {
        wait(NULL);
        return 0;
    }

    ret = sig_mask(SIG_UNBLOCK);
    if (ret < 0)
        return ret;

    setsid();
    setpgid(0, 0);

    ret = putenv(envp[0]);
    if (ret < 0) {
        perror("initialize default path environment");
        return -errno;
    }

    ret = execvpe(argv[0], argv, envp);
    if (ret < 0) {
        perror("exec application");
        return -errno;
    }

    return 0;
}

static int nsm_pcrs_extend(void *rootfs_archive, uint32_t archive_size,
                           char *path, char **argv, char **envp)
{
    uint32_t pcr_data_size, total, to_write;
    uint8_t pcr_data[256];
    int ret, nsm_fd, i;
    char *exec_ptr;
    void *idx;

    nsm_fd = nsm_lib_init();
    if (nsm_fd < 0) {
        perror("unable to open NSM guest module");
        return -errno;
    }

    idx = rootfs_archive;
    total = archive_size;
    while (total > 0) {
        to_write = (total < NSM_PCR_CHUNK_SIZE) ? total : NSM_PCR_CHUNK_SIZE;
        ret = nsm_extend_pcr(nsm_fd, NSM_PCR_ROOTFS, idx, to_write,
                             (void *)pcr_data, &pcr_data_size);
        if (ret != ERROR_CODE_SUCCESS)
            goto done;

        idx += to_write;
        total -= to_write;
    }

    exec_ptr = path;
    ret = nsm_extend_pcr(nsm_fd, NSM_PCR_EXEC_DATA, (uint8_t *)exec_ptr,
                         strlen(exec_ptr), (void *)pcr_data, &pcr_data_size);
    if (ret != ERROR_CODE_SUCCESS)
        goto done;

    for (i = 0; (exec_ptr = argv[i]) != NULL; ++i) {
        ret =
            nsm_extend_pcr(nsm_fd, NSM_PCR_EXEC_DATA, (uint8_t *)exec_ptr,
                           strlen(exec_ptr), (void *)pcr_data, &pcr_data_size);
        if (ret != ERROR_CODE_SUCCESS)
            goto done;
    }

    for (i = 0; (exec_ptr = envp[i]) != NULL; ++i) {
        ret =
            nsm_extend_pcr(nsm_fd, NSM_PCR_EXEC_DATA, (uint8_t *)exec_ptr,
                           strlen(exec_ptr), (void *)pcr_data, &pcr_data_size);
        if (ret != ERROR_CODE_SUCCESS)
            goto done;
    }

    ret = nsm_lock_pcrs(nsm_fd, NSM_PCR_EXEC_DATA);
    if (ret != ERROR_CODE_SUCCESS)
        goto done;

    ret = 0;

done:
    nsm_lib_exit(nsm_fd);

    return -ret;
}

int main(int argc, char *argv[])
{
    char *exec_path, **exec_argv, **exec_envp;
    uint32_t archive_size;
    void *rootfs_archive;
    int ret, sock_fd;

    // Block all signals.
    ret = sig_mask(SIG_BLOCK);
    if (ret < 0)
        exit(ret);

    // Initialize early debug output with /dev/console.
    ret = console_init();
    if (ret < 0)
        exit(ret);

    // Initialize the NSM kernel module.
    ret = nsm_init();
    if (ret < 0)
        exit(ret);

    sock_fd = vsock_hypervisor_signal();
    if (sock_fd < 0)
        exit(ret);

    ret = vsock_rcv(sock_fd, &rootfs_archive, &archive_size);
    if (ret < 0) {
        close(sock_fd);
        exit(ret);
    }

    ret = vsock_rcv(sock_fd, (void **)&exec_path, NULL);
    if (ret < 0) {
        close(sock_fd);
        exit(ret);
    }

    ret = vsock_char_list_build(sock_fd, &exec_argv);
    if (ret < 0) {
        close(sock_fd);
        exit(ret);
    }

    ret = vsock_char_list_build(sock_fd, &exec_envp);
    if (ret < 0) {
        close(sock_fd);
        exit(ret);
    }

    close(sock_fd);

    ret = nsm_pcrs_extend(rootfs_archive, archive_size, exec_path, exec_argv,
                          exec_envp);
    if (ret < 0)
        exit(ret);

    ret = archive_extract(rootfs_archive, archive_size);
    if (ret < 0)
        exit(ret);

    ret = rootfs_mount();
    if (ret < 0)
        exit(ret);

    // Ensure the container /dev is initialized as well.
    ret = mount("dev", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < 0 && errno != EBUSY) {
        perror("mount");
        return ret;
    }

    ret = filesystem_init();
    if (ret < 0)
        exit(ret);

    ret = cgroups_init();
    if (ret < 0)
        exit(ret);

    ret = launch(exec_argv, exec_envp);
    if (ret < 0)
        exit(ret);

    exit(0);
    reboot(RB_AUTOBOOT);

    // Unreachable.
    return -1;
}

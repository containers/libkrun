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
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <nsm.h>

#include "include/archive.h"
#include "include/args_reader.h"
#include "include/fs.h"
#include "include/tap_afvsock.h"

#include <linux/vm_sockets.h>
#include <sys/socket.h>

#define finit_module(fd, param_values, flags)                                  \
    (int)syscall(__NR_finit_module, fd, param_values, flags)

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
        return -errno;
    }

    // Block/unblock the signals. This essentially blocks/unblocks all signals
    // to the process.
    ret = sigprocmask(mask, &set, 0);
    if (ret < 0) {
        perror("sigprocmask");
        return -errno;
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

    // Close the file descriptor.
    ret = close(fd);
    if (ret < 0) {
        perror("nsm.ko close");
        return -errno;
    }

    // The NSM module file is no longer needed, remove it.
    ret = unlink(file_name);
    if (ret < 0) {
        perror("nsm.ko unlink");
        return -errno;
    }

    return 0;
}

/*
 * Mount the extracted rootfs and switch the root directory to it.
 */
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

static int app_stdio_output(void)
{
    int streams[2] = {STDOUT_FILENO, STDERR_FILENO};
    struct sockaddr_vm addr;
    struct timeval timeval;
    int ret, sock_fd, i;

    sock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("unable to create guest socket");
        return -errno;
    }

    bzero((char *)&addr, sizeof(struct sockaddr_vm));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_HOST;
    addr.svm_port = 8081;

    memset(&timeval, 0, sizeof(struct timeval));
    timeval.tv_sec = 5;

    ret = setsockopt(sock_fd, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
                     (void *)&timeval, sizeof(struct timeval));
    if (ret < 0) {
        perror("unable to connect to host socket");
        close(sock_fd);
        return -errno;
    }

    ret = connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("unable to connect to host socket");
        close(sock_fd);
        return -errno;
    }

    for (i = 0; i < 2; i++) {
        ret = dup2(sock_fd, streams[i]);
        if (ret < 0) {
            fprintf(stderr, "unable to redirect stream [%d] to socket: %s\n",
                    streams[i], strerror(errno));
            close(sock_fd);
            return -errno;
        }
    }

    return sock_fd;
}

/*
 * Launch the application specified with argv and envp.
 */
pid_t launch(char **argv, char **envp)
{
    int ret, pid;

    // Fork the process.
    pid = fork();
    if (pid < 0) {
        perror("launch fork");
        return -errno;
    } else if (pid != 0) {
        // Parent process. Wait for the child to end before exiting.
        wait(NULL);
        return 0;
    }

    // Unblock all signals.
    ret = sig_mask(SIG_UNBLOCK);
    if (ret < 0)
        return ret;

    // Create a new session and set the process group ID.
    setsid();

    // Set the PGID to the same as the process ID.
    setpgid(0, 0);

    // Add the envp to the environment variables.
    ret = putenv(envp[0]);
    if (ret < 0) {
        perror("initialize default path environment");
        return -errno;
    }

    // Execute the process.
    ret = execvpe(argv[0], argv, envp);
    if (ret < 0) {
        perror("exec application");
        return -errno;
    }

    return 0;
}

/*
 * Measure the enclave rootfs and execution variables (path, argv, envp) with
 * the NSM PCRs.
 *
 * NSM PCR 16 contains the measurement of the root filesystem.
 * NSM PCR 17 contains the measurement of the execution variables (path, argv,
 * envp).
 */
static int nsm_pcrs_exec_path_extend(int nsm_fd, char *path, char **argv,
                                     char **envp)
{
    uint32_t pcr_data_size;
    uint8_t pcr_data[256];
    char *exec_ptr;
    int ret, i;

    pcr_data_size = 256;

    // Measure the execution path with NSM PCR 17.
    exec_ptr = path;
    ret = nsm_extend_pcr(nsm_fd, NSM_PCR_EXEC_DATA, (uint8_t *)exec_ptr,
                         strlen(exec_ptr), (void *)pcr_data, &pcr_data_size);
    if (ret != ERROR_CODE_SUCCESS)
        goto out;

    // Measure each execution argument with NSM PCR 17.
    for (i = 0; (exec_ptr = argv[i]) != NULL; ++i) {
        ret =
            nsm_extend_pcr(nsm_fd, NSM_PCR_EXEC_DATA, (uint8_t *)exec_ptr,
                           strlen(exec_ptr), (void *)pcr_data, &pcr_data_size);
        if (ret != ERROR_CODE_SUCCESS)
            goto out;
    }

    // Measure each environment variable with NSM PCR 17.
    for (i = 0; (exec_ptr = envp[i]) != NULL; ++i) {
        ret =
            nsm_extend_pcr(nsm_fd, NSM_PCR_EXEC_DATA, (uint8_t *)exec_ptr,
                           strlen(exec_ptr), (void *)pcr_data, &pcr_data_size);
        if (ret != ERROR_CODE_SUCCESS)
            goto out;
    }

    ret = 0;

out:
    return -ret;
}

/*
 * Lock PCRs measured by initramfs and close the NSM handle.
 */
static int nsm_exit(int nsm_fd)
{
    int ret;

    /*
     * Lock PCRs 16 and 17 so they cannot be extended further. This is to ensure
     * there can no further data measured other than the rootfs and execution
     * variables.
     */
    ret = nsm_lock_pcrs(nsm_fd, NSM_PCR_EXEC_DATA);
    if (ret != ERROR_CODE_SUCCESS)
        goto out;

    // Close the NSM device handle.
    nsm_lib_exit(nsm_fd);

    ret = 0;

out:
    return -ret;
}

int main(int argc, char *argv[])
{
    int ret, nsm_fd, shutdown_fd, pid, app_status;
    struct enclave_args args;
    uint64_t sfd_val;

    memset(&args, 0, sizeof(struct enclave_args));

    // Block all signals.
    ret = sig_mask(SIG_BLOCK);
    if (ret < 0)
        goto out;

    // Initialize early debug output with /dev/console.
    ret = console_init();
    if (ret < 0)
        goto out;

    // Initialize the NSM kernel module.
    ret = nsm_init();
    if (ret < 0)
        goto out;

    ret = args_reader_read(&args);
    if (ret < 0)
        goto out;

    // Create a handle to the NSM.
    nsm_fd = nsm_lib_init();
    if (nsm_fd < 0) {
        perror("unable to open NSM guest module");
        ret = -errno;
        goto out;
    }

    // Measure the rootfs and execution variables in the NSM PCRs.
    ret = nsm_pcrs_exec_path_extend(nsm_fd, args.exec_path, args.exec_argv,
                                    args.exec_envp);
    if (ret < 0)
        goto out;

    // Extract the rootfs from memory and write it to the enclave filesystem.
    ret =
        archive_extract(nsm_fd, args.rootfs_archive, args.rootfs_archive_size);
    if (ret < 0)
        goto out;

    // Lock NSM PCRs and close handle.
    ret = nsm_exit(nsm_fd);
    if (ret < 0)
        goto out;

    // Mount the root filesystem.
    ret = rootfs_mount();
    if (ret < 0)
        goto out;

    // Ensure the container /dev is initialized as well.
    ret = mount("dev", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL);
    if (ret < 0 && errno != EBUSY) {
        perror("mount");
        return ret;
    }

    // Initialize the rest of the filesystem.
    ret = filesystem_init();
    if (ret < 0)
        goto out;

    // Initialize the cgroups.
    ret = cgroups_init();
    if (ret < 0)
        goto out;

    shutdown_fd = eventfd(0, 0);
    if (shutdown_fd < 0) {
        perror("creating shutdown FD");
        ret = -errno;
        goto out;
    }

    // Initialize the network TAP device.
    if (args.network_proxy) {
        ret = tap_afvsock_init(shutdown_fd);
        if (ret < 0)
            goto out;
    }

    if (!args.debug) {
        ret = app_stdio_output();
        if (ret < 0)
            goto out;
    }

    pid = fork();
    switch (pid) {
    case -1:
        perror("launch fork");
        ret = -errno;
        break;
    case 0:
        // Execute the enclave application.
        ret = launch(args.exec_argv, args.exec_envp);
        break;
    default:
        sfd_val = 1;
        wait(&app_status);

        ret = write(shutdown_fd, &sfd_val, sizeof(uint64_t));
        if (ret < 0) {
            perror("write shutdown FD");
            ret = -errno;
            goto out;
        }

        /*
         * TODO: Remove this call to sleep. Instead, receive a signal from the
         * network proxy that the vsock and TUN file descriptors have been
         * closed before exiting the parent process (i.e. the VM in general).
         */
        sleep(5);

        ret = app_status;
        break;
    }

out:
    exit(ret);
    reboot(RB_AUTOBOOT);

    // Unreachable.
    return -1;
}

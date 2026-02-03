// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <nsm.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "device/include/device.h"
#include "include/archive.h"
#include "include/args_reader.h"
#include "include/fs.h"

#define finit_module(fd, param_values, flags)                                  \
    (int)syscall(__NR_finit_module, fd, param_values, flags)

#define NSM_PCR_EXEC_DATA 17

#define NSM_PCR_CHUNK_SIZE 0x800 // 2 KiB.

enum {
    VSOCK_PORT_OFFSET_ARGS_READER = 1,
    VSOCK_PORT_OFFSET_NET = 2,
    VSOCK_PORT_OFFSET_OUTPUT = 3,
    VSOCK_PORT_OFFSET_APP_RET_CODE = 4,
    VSOCK_PORT_OFFSET_SIGNAL_HANDLER = 5,
};

/*
 * Load the NSM kernel module.
 */
static int nsm_load(void)
{
    const char *file_name = "nsm.ko";
    int fd, ret;

    // Open and load the kernel module.
    fd = open(file_name, O_RDONLY | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT)
        return 0;
    else if (fd < 0) {
        perror("nsm.ko open");
        return -errno;
    }

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
static int rootfs_mount(void)
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

/*
 * Launch the application specified with argv and envp.
 */
static pid_t launch(char **argv, char **envp)
{
    int ret;

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

    return ret;
}

/*
 * Measure the enclave execution environment (path, argv, envp) in NSM PCR 17.
 *
 * NSM PCR 17 contains the measurement of the execution environment (path, argv,
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

    // Measure the execution path.
    exec_ptr = path;
    ret = nsm_extend_pcr(nsm_fd, NSM_PCR_EXEC_DATA, (uint8_t *)exec_ptr,
                         strlen(exec_ptr), (void *)pcr_data, &pcr_data_size);
    if (ret != ERROR_CODE_SUCCESS)
        goto out;

    // Measure each execution argument.
    for (i = 0; (exec_ptr = argv[i]) != NULL; ++i) {
        ret =
            nsm_extend_pcr(nsm_fd, NSM_PCR_EXEC_DATA, (uint8_t *)exec_ptr,
                           strlen(exec_ptr), (void *)pcr_data, &pcr_data_size);
        if (ret != ERROR_CODE_SUCCESS)
            goto out;
    }

    // Measure each environment variable.
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
 * Lock PCRs measured by init process and close the NSM handle.
 */
static int nsm_exit(int nsm_fd)
{
    int ret;

    /*
     * Lock PCRs 16 and 17 so they cannot be extended further. This is to ensure
     * there can no further data measured other than the rootfs and execution
     * environment.
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

/*
 * Fetch the enclave VM's CID in order to calculate vsock port offsets for host
 * communication.
 */
static unsigned int cid_fetch(void)
{
    unsigned int cid;
    int ret, fd;

    fd = open("/dev/vsock", O_RDONLY);
    if (fd < 0) {
        perror("unable to open /dev/vsock to fetch enclave CID:");
        return 0;
    }

    ret = ioctl(fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid);
    close(fd);

    if (ret < 0) {
        perror("unable to fetch VM CID:");
        return 0;
    }

    return cid;
}

/*
 * Forward the application return code to the host.
 */
static int app_ret_write(int code, unsigned int cid)
{
    unsigned int vsock_port;
    struct sockaddr_vm addr;
    struct timeval timeval;
    int ret, sock_fd;

    sock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("unable to open application return vsock");
        return -errno;
    }

    vsock_port = cid + VSOCK_PORT_OFFSET_APP_RET_CODE;

    bzero((char *)&addr, sizeof(struct sockaddr_vm));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_HOST;
    addr.svm_port = vsock_port;

    memset(&timeval, 0, sizeof(struct timeval));
    timeval.tv_sec = 5;

    /*
     * The host needs to join all device proxy threads before reading the return
     * code. Allow some time for the host to connect to the return code vsock.
     */
    ret = setsockopt(sock_fd, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
                     (void *)&timeval, sizeof(struct timeval));
    if (ret < 0) {
        perror("unable to set application return vsock connect timeout");
        close(sock_fd);
        return -errno;
    }

    ret = connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("unable to connect to application return vsock");
        close(sock_fd);
        return -errno;
    }

    // Write the return code.
    ret = write(sock_fd, (void *)&code, sizeof(int));
    if (ret < sizeof(int)) {
        perror("unable to write application return code");
        close(sock_fd);
        return -errno;
    }

    /*
     * Read a return code (value is irrelevant) from the host. This is to ensure
     * that the host was able to read the return code from the vsock before the
     * enclave exits.
     */
    ret = read(sock_fd, (void *)&code, sizeof(int));
    if (ret < sizeof(int)) {
        perror("unable to read close signal from application return vsock");
        close(sock_fd);
        return -errno;
    }

    close(sock_fd);

    return 0;
}

/*
 * Initialize each configured device proxy for the enclave.
 */
static int proxies_init(int cid, struct enclave_args *args, int shutdown_fd)
{
    struct sigaction sa;
    int ret;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = device_proxy_sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL);

    /*
     * Each proxy will send a SIGUSR1 message to indicate when it has started.
     * Enable this signal so the main process can wait and be notified when each
     * proxy has initialized itself.
     */
    ret = sigaction(SIGUSR1, &sa, NULL);
    if (ret < 0) {
        perror("sigaction enable SIGUSR1 for device proxies");
        return -errno;
    }

    /*
     * If not running in debug mode, initialize the application output proxy.
     * In debug mode, the enclave uses the console (which is already connected)
     * for output.
     */
    if (!args->debug) {
        ret = device_init(KRUN_NE_DEV_APP_OUTPUT_STDIO,
                          cid + VSOCK_PORT_OFFSET_OUTPUT, shutdown_fd);
    }

    // Initialize the network proxy if configured.
    if (args->network_proxy) {
        ret = device_init(KRUN_NE_DEV_NET_TAP_AF_VSOCK,
                          cid + VSOCK_PORT_OFFSET_NET, shutdown_fd);
        if (ret < 0)
            return ret;
    }

    /*
     * The signal proxy is always initialized to allow the host to send signals
     * to the enclave.
     */
    ret = device_init(KRUN_NE_DEV_SIGNAL_HANDLER,
                      cid + VSOCK_PORT_OFFSET_SIGNAL_HANDLER, shutdown_fd);

    return ret;
}

/*
 * Close and exit each device proxy.
 */
static int proxies_exit(struct enclave_args *args, int shutdown_fd)
{
    uint64_t sfd_val;
    int ret;

    /*
     * The shutdown value is irrelevant, it acts as a signal to all device proxy
     * threads that the enclave is exiting. Upon receiving this signal, each
     * device proxy will close their respective vsock and exit.
     */
    sfd_val = 1;
    ret = write(shutdown_fd, &sfd_val, sizeof(uint64_t));
    if (ret < 0) {
        perror("write shutdown FD");
        ret = -errno;
    }

    // If not in debug mode, close the application output vsock.
    if (!args->debug)
        app_stdio_close();

    return ret;
}

// The PID of the application process.
static pid_t KRUN_NITRO_APP_PID = -1;
// Indicates if a SIGTERM signal was caught by the enclave signal handler.
static bool KRUN_NITRO_SIGTERM_CAUGHT = false;

/*
 * Forward a signal from the signal handler to the application process.
 * Currently, only SIGTERM is supported.
 */
void shutdown_sig_handler(int sig)
{
    if ((sig == SIGTERM) && (KRUN_NITRO_APP_PID > 0)) {
        // Send the signal to the application process.
        kill(KRUN_NITRO_APP_PID, sig);
        // Indicate that the SIGTERM signal was caught.
        KRUN_NITRO_SIGTERM_CAUGHT = true;
    }
}

int main(int argc, char *argv[])
{
    int ret, nsm_fd, shutdown_fd, pid, ret_code;
    struct enclave_args args;
    struct sigaction sa;
    unsigned int cid;
    sigset_t sigset;

    ret = -1;
    memset(&args, 0, sizeof(struct enclave_args));

    // Block all signals.
    ret = sigfillset(&sigset);
    if (ret < 0) {
        perror("sigfillset");
        return -errno;
    }

    ret = sigprocmask(SIG_BLOCK, &sigset, 0);
    if (ret < 0) {
        perror("sigprocmask");
        return -errno;
    }

    // Initialize early debug output with /dev/console.
    ret = console_init();
    if (ret < 0)
        goto out;

    // Get the enclave's context ID.
    cid = cid_fetch();
    if (cid == 0)
        goto out;

    // Initialize the NSM kernel module.
    ret = nsm_load();
    if (ret < 0)
        goto out;

    // Read the enclave arguments from the host.
    ret = args_reader_read(&args, cid + VSOCK_PORT_OFFSET_ARGS_READER);
    if (ret < 0)
        goto out;

    // Create a handle to the NSM.
    nsm_fd = nsm_lib_init();
    if (nsm_fd < 0) {
        perror("unable to open NSM guest module");
        ret = -errno;
        goto out;
    }

    // Measure the rootfs and execution environment in the NSM PCRs.
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

    // Initialize the rest of the filesystem.
    ret = filesystem_init();
    if (ret < 0)
        goto out;

    // Initialize the cgroups.
    ret = cgroups_init();
    if (ret < 0)
        goto out;

    /*
     * Create a shutdown eventfd that can be written to in order to notify each
     * device proxy to close and exit at some point.
     */
    shutdown_fd = eventfd(0, 0);
    if (shutdown_fd < 0) {
        perror("creating shutdown FD");
        ret = -errno;
        goto out;
    }

    // Initialize each configured device proxy.
    ret = proxies_init(cid, &args, shutdown_fd);
    if (ret < 0)
        goto out;

    // Unblock all signals.
    ret = sigprocmask(SIG_UNBLOCK, &sigset, 0);
    if (ret < 0) {
        perror("sigprocmask unblock all signals");
        return -errno;
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
        /*
         * Store the application process' PID in the event of a signal needing
         * to be forwarded to it.
         */
        KRUN_NITRO_APP_PID = pid;

        /*
         * Initialize the shutdown handler for signals to be forwarded to the
         * application process.
         */
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_handler = shutdown_sig_handler;

        ret = sigaction(SIGTERM, &sa, NULL);
        if (ret < 0) {
            perror("sigaction enable SIGUSR1 for device proxies");
            return -errno;
        }

        // Wait for the application process to exit.
        waitpid(pid, &ret_code, 0);

        /*
         * If the process was ended by a signal, the return code may represent a
         * value that under normal circumstances would indicate an error.
         * Therefore, if the application ended from a signal, zero-out the
         * return code (indicating that the application process exited
         * gracefully).
         */
        if (KRUN_NITRO_SIGTERM_CAUGHT)
            ret_code = 0;

        // Close and exit each device proxy.
        ret = proxies_exit(&args, shutdown_fd);
        if (ret < 0)
            goto out;

        // Write the return code to the host.
        ret = app_ret_write(ret_code, cid);
    }

out:
    return ret;
}

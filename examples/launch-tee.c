/*
 * This is an example implementing chroot-like functionality with libkrun.
 *
 * It executes the requested command (relative to NEWROOT) inside a fresh
 * Virtual Machine created and managed by libkrun.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libkrun.h>

#define MAX_ARGS_LEN 4096
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

int main(int argc, char *const argv[])
{
    const char *const port_map[] =
    {
        "18000:8000",
        0
    };
    const char *const rlimits[] =
    {
        // RLIMIT_NPROC = 6
        "6=4096:8192",
        0
    };
    static const struct option long_opts[] = {
        { "td-shim", required_argument, 0, 's' },
        { 0, 0, 0, 0 }
    };
    const char *td_shim_path = NULL;
    char current_path[MAX_PATH];
    char volume_tail[] = ":/work\0";
    char *volume;
    int volume_len;
    int ctx_id;
    int err;
    int i;
    int opt;

    while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's':
            td_shim_path = optarg;
            break;
        default:
            printf("Usage: %s [--td-shim PATH] ROOT_DISK_IMAGE TEE_CONFIG_FILE DATA_DISK_IMAGE\n", argv[0]);
            return -1;
        }
    }

    if (argc - optind != 3) {
        printf("Invalid arguments\n");
        printf("Usage: %s [--td-shim PATH] ROOT_DISK_IMAGE TEE_CONFIG_FILE DATA_DISK_IMAGE\n", argv[0]);
        return -1;
    }

    // Set the log level to "error".
    err = krun_set_log_level(1);
    if (err) {
        errno = -err;
        perror("Error configuring log level");
        return -1;
    }

    // Create the configuration context.
    ctx_id = krun_create_ctx();
    if (ctx_id < 0) {
        errno = -ctx_id;
        perror("Error creating configuration context");
        return -1;
    }

    // Configure the number of vCPUs (1) and the amount of RAM (2 GiB).
    if (err = krun_set_vm_config(ctx_id, 1, 2048)) {
        errno = -err;
        perror("Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    // Use the first positional argument as the disk image containing the root fs.
    if (err = krun_add_disk2(ctx_id, "root", argv[optind], KRUN_DISK_FORMAT_RAW, false)) {
        errno = -err;
        perror("Error configuring root disk image");
        return -1;
    }

    if (getcwd(&current_path[0], MAX_PATH) == NULL) {
        errno = -err;
        perror("Error getting current directory");
        return -1;
    }

    volume_len = strlen(current_path) + strlen(volume_tail) + 1;
    volume = malloc(volume_len);
    if (volume == NULL) {
        errno = -err;
        perror("Error allocating memory for volume string");
    }

    // Map port 18000 in the host to 8000 in the guest.
    if (err = krun_set_port_map(ctx_id, &port_map[0])) {
        errno = -err;
        perror("Error configuring port map");
        return -1;
    }

    // Configure the rlimits that will be set in the guest
    if (err = krun_set_rlimits(ctx_id, &rlimits[0])) {
        errno = -err;
        perror("Error configuring rlimits");
        return -1;
    }

    // Set the working directory to "/", just for the sake of completeness.
    if (err = krun_set_workdir(ctx_id, "/")) {
        errno = -err;
        perror("Error configuring \"/\" as working directory");
        return -1;
    }

    if (err = krun_set_tee_config_file(ctx_id, argv[optind + 1])) {
        errno = -err;
        perror("Error setting the TEE config file");
        return -1;
    }

    if (td_shim_path != NULL) {
        if (err = krun_set_tee_firmware(ctx_id, KRUN_TEE_FW_TDSHIM, td_shim_path)) {
            errno = -err;
            perror("Error setting TD-Shim firmware path");
            return -1;
        }
    }

    if (err = krun_add_disk2(ctx_id, "data", argv[optind + 2], KRUN_DISK_FORMAT_RAW, false)) {
        errno = -err;
        perror("Error configuring the TEE config data disk");
        return -1;
    }

    // Serial console (ttyS0) for kernel log output only (no stdin).
    if (err = krun_add_serial_console_default(ctx_id, -1, STDOUT_FILENO)) {
        errno = -err;
        perror("Error adding serial console");
        return -1;
    }

    // Disable the implicit virtio console: without explicit TTY fds, the implicit
    // console creates krun-stdin/krun-stdout ports connected to /dev/null.
    // setup_redirects() in init.krun finds those ports and silently redirects the
    // shell's stdin/stdout to /dev/null, making all I/O disappear.
    if (err = krun_disable_implicit_console(ctx_id)) {
        errno = -err;
        perror("Error disabling implicit console");
        return -1;
    }

    // Virtio console (hvc0) for interactive shell I/O.
    if (err = krun_add_virtio_console_default(ctx_id, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO)) {
        errno = -err;
        perror("Error adding virtio console");
        return -1;
    }

    if (err = krun_split_irqchip(ctx_id, true)) {
        errno = -err;
        perror("Error setting split IRQCHIP property");
        return -1;
    }

    // Start and enter the microVM. Unless there is some error while creating the microVM
    // this function never returns.
    if (err = krun_start_enter(ctx_id)) {
        errno = -err;
        perror("Error creating the microVM");
        return -1;
    }

    // Not reached.
    return 0;
}

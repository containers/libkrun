/*
 * This is an example implementing chroot-like functionality with libkrun.
 *
 * It executes the requested command (relative to NEWROOT) inside a fresh
 * Virtual Machine created and managed by libkrun.
 */

#include <errno.h>
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
    char *const port_map[] =
    {
        "18000:8000",
        0
    };
    char *const rlimits[] =
    {
        // RLIMIT_NPROC = 6
        "6=4096:8192",
        0
    };
    char current_path[MAX_PATH];
    char volume_tail[] = ":/work\0";
    char *volume;
    int volume_len;
    int ctx_id;
    int err;
    int i;

    if (argc < 3 || argc > 4) {
        printf("Invalid arguments\n");
        printf("Usage: %s ROOT_DISK_IMAGE TEE_CONFIG_FILE [DATA_DISK_IMAGE]\n", argv[0]);
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
        errno = -err;
        perror("Error creating configuration context");
        return -1;
    }

    // Configure the number of vCPUs (1) and the amount of RAM (2 GiB).
    if (err = krun_set_vm_config(ctx_id, 1, 2048)) {
        errno = -err;
        perror("Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    // Use the first command line argument as the disk image containing the root fs.
    if (err = krun_set_root_disk(ctx_id, argv[1])) {
        errno = -err;
        perror("Error configuring root disk image");
        return -1;
    }

    // Use the third (optional) command line argument as the disk image containing a data disk.
    if (argc > 3) {
        if (err = krun_set_data_disk(ctx_id, argv[3])) {
            errno = -err;
            perror("Error configuring data disk image");
            return -1;
        }
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

    if (err = krun_set_tee_config_file(ctx_id, argv[2])) {
        errno = -err;
        perror("Error configuring the attestation server");
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

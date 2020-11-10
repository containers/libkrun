/*
 * This is an example implementing chroot-like functionality with libkrun.
 *
 * It executes the requested command (relative to NEWROOT) inside a fresh
 * Virtual Machine created and managed by libkrun.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <libkrun.h>

#define MAX_ARGS_LEN 4096

int main(int argc, char *const argv[])
{
    char *const envp[] =
    {
        "TEST=works",
        0
    };
    int ctx_id;
    int err;
    int i;

    if (argc < 3) {
        printf("Invalid arguments\n");
        printf("Usage: %s NEWROOT COMMAND [ARG...]\n", argv[0]);
        return -1;
    }

    // Set the log level to "off".
    err = krun_set_log_level(0);
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

    // Configure the number of vCPUs (1) and the amount of RAM (512 MiB).
    if (err = krun_set_vm_config(ctx_id, 1, 512)) {
        errno = -err;
        perror("Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    // Use the first command line argument as the path to be used as root.
    if (err = krun_set_root(ctx_id, argv[1])) {
        errno = -err;
        perror("Error configuring root path");
        return -1;
    }

    // Set the working directory to "/", just for the sake of completeness.
    if (err = krun_set_workdir(ctx_id, "/")) {
        errno = -err;
        perror("Error configuring \"/\" as working directory");
        return -1;
    }

    // Use the second argument as the path of the binary to be executed in the isolated
    // context, relative to the root path.
    if (err = krun_set_exec(ctx_id, argv[2], &argv[3], &envp[0])) {
        errno = -err;
        perror("Error configuring the parameters for the executable to be run");
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

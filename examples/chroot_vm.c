/*
 * This is an example implementing chroot-like functionality with libkrun.
 *
 * It executes the requested command (relative to NEWROOT) inside a fresh
 * Virtual Machine created and managed by libkrun.
 */

#include <stdio.h>
#include <string.h>
#include <libkrun.h>

#define MAX_ARGS_LEN 4096

int main(int argc, void **argv)
{
    struct krun_config config;
    char args[MAX_ARGS_LEN] = "\0";
    char env_line[] = "\0";
    int args_len = 0;
    int i;

    if (argc < 3) {
        printf("Invalid arguments\n");
        printf("Usage: %s NEWROOT COMMAND [ARG...]\n", argv[0]);
        return -1;
    }

    memset(&config, 0,  sizeof(config));

    // Set the size of the config struct known at build time.
    config.config_size = sizeof(config);
    // Set the krun's verbosity to the minimum.
    config.log_level = 0;
    // Request a single vCPU.
    config.num_vcpus = 1;
    // Request 512 MB.
    config.ram_mib = 512;
    // Use the first argument as the root directory.
    config.root_dir = argv[1];
    // Use the second argument as the process to be isolated.
    config.exec_path = argv[2];
    // Point the arguments line to our own (empty, for the moment) args string.
    config.args = &args[0];

    // If we have additional arguments, collect them into "args".
    for (i = 3; i < argc; i++) {
        // We need to add an space as a separator.
        int len = strlen(argv[i]) + 1;

        if ((len + args_len) >= (MAX_ARGS_LEN - 1)) {
            printf("Too many arguments\n");
            return -1;
        }

        strncpy(&args[args_len], argv[i], MAX_ARGS_LEN - args_len - 1);
        args_len += len;
        args[args_len - 1] = ' ';
    }
    args[args_len] = '\0';

    // Pass an empty string so libkrun won't autogenerate the environment
    // line by collecting this process environment variables.
    config.env_line = &env_line[0];

    krun_exec(&config);

    return 0;
}

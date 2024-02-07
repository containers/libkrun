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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <libkrun.h>
#include <getopt.h>
#include <stdbool.h>
#include <assert.h>

#define MAX_ARGS_LEN 4096
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

static void print_help(char *const name)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] DISK\n"
        "OPTIONS: \n"
        "        -h    --help                Show help\n"
        "              --passt-socket=PATH   Connect to passt socket at PATH"
        "\n"
        "DISK:   path to the vm's disk image in raw format\n",
        name
    );
}

static const struct option long_options[] = {
    { "help", no_argument, NULL, 'h' },
    { "passt-socket", required_argument, NULL, 'P' },
    { NULL, 0, NULL, 0 }
};

struct cmdline {
    bool show_help;
    char const *passt_socket_path;
    char const *disk_image;
};

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    assert(cmdline != NULL);

    // set the defaults
    *cmdline = (struct cmdline){
        .show_help = false,
        .passt_socket_path = "/tmp/network.sock",
        .disk_image = NULL,
    };

    int option_index = 0;
    int c;
    // the '+' in optstring is a GNU extension that disables permutating argv
    while ((c = getopt_long(argc, argv, "+h", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmdline->show_help = true;
            return true;
        case 'P':
            cmdline->passt_socket_path = optarg;
            break;
        case '?':
            return false;
        default:
            fprintf(stderr, "internal argument parsing error (returned character code 0x%x)\n", c);
            return false;
        }
    }

    if (optind <= argc - 1) {
        cmdline->disk_image = argv[optind];
        return true;
    }

    if (optind == argc) {
        fprintf(stderr, "Missing DISK argument\n");
    }

    return false;
}

int connect_to_passt(char *socket_path)
{
    struct sockaddr_un addr;
    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("Failed to create passt socket fd");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(socket_fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Failed to bind passt socket");
        return -1;
    }

    return socket_fd;
}

int main(int argc, char *const argv[])
{
    int ctx_id;
    int err;
    struct cmdline cmdline;

    if (!parse_cmdline(argc, argv, &cmdline)) {
        putchar('\n');
        print_help(argv[0]);
        return -1;
    }

    if (cmdline.show_help){
        print_help(argv[0]);
        return 0;
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
        errno = -ctx_id;
        perror("Error creating configuration context");
        return -1;
    }

    // Configure the number of vCPUs (2) and the amount of RAM (1024 MiB).
    if (err = krun_set_vm_config(ctx_id, 2, 1024)) {
        errno = -err;
        perror("Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    if (err = krun_set_root_disk(ctx_id, cmdline.disk_image)) {
        errno = -err;
        perror("Error configuring disk image");
        return -1;
    }

    int passt_fd = connect_to_passt(cmdline.passt_socket_path);

    if (passt_fd < 0) {
      return -1;
    }

    if (err = krun_set_passt_fd(ctx_id, passt_fd)) {
      errno = -err;
      perror("Error configuring net mode");
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

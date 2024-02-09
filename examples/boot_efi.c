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
#include <pthread.h>

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

#define SHUTDOWN_SOCK_PATH  "/tmp/krun_shutdown.sock"

void *listen_shutdown_request(void *opaque)
{
    int server_sock, client_sock, len, ret;
    int bytes_rec = 0;
    int shutdown_efd = (int) opaque;
    char buf[8];
    struct sockaddr_un server_sockaddr;
    struct sockaddr_un client_sockaddr;
    memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(&client_sockaddr, 0, sizeof(struct sockaddr_un));

    server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sock == -1){
        perror("Error creating socket");
        exit(1);
    }

    server_sockaddr.sun_family = AF_UNIX;
    strcpy(server_sockaddr.sun_path, SHUTDOWN_SOCK_PATH);
    len = sizeof(server_sockaddr);

    unlink(SHUTDOWN_SOCK_PATH);
    ret = bind(server_sock, (struct sockaddr *) &server_sockaddr, len);
    if (ret == -1){
        perror("Error binding socket");
        close(server_sock);
        exit(1);
    }

    ret = listen(server_sock, 1);
    if (ret == -1){
        perror("Error listening on socket");
        close(server_sock);
        exit(1);
    }

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *) &client_sockaddr, &len);
        if (client_sock == -1){
            perror("Error accepting connection");
            close(server_sock);
            close(client_sock);
            exit(1);
        }

        ret = write(shutdown_efd, &buf[0], 8);
        if (ret < 0) {
            perror("Error writing to eventfd");
        }

        close(client_sock);
    }
}

int main(int argc, char *const argv[])
{
    int ctx_id;
    int err;
    pthread_t thread;
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

    int efd = krun_get_shutdown_eventfd(ctx_id);
    if (efd < 0) {
        perror("Can't get shutdown eventfd");
        return -1;
    }

    // Spawn a thread to listen on "/tmp/krun_shutdown.sock" for a request to send
    // a shutdown signal to the guest.
    pthread_create(&thread, NULL, listen_shutdown_request, (void*) efd);

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

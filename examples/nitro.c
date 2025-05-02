/*
 * This is an example implementing running an example AWS nitro enclave with
 * libkrun.
 *
 * Given a nitro enclave image, run the image in a nitro enclave with 1 vCPU and
 * 256 MiB of memory allocated.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libkrun.h>
#include <getopt.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>

#define MAX_ARGS_LEN 4096
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

#define IPC_SOCK_PATH "/tmp/krun_nitro_example_ipc.sock"

static void print_help(char *const name)
{
    fprintf(stderr,
        "Usage: %s EIF_FILE [COMMAND_ARGS...]\n"
        "OPTIONS: \n"
        "        -h    --help                Show help\n"
        "\n"
        "ENCLAVE_IMAGE:     The enclave image to run\n",
        name
    );
}

static const struct option long_options[] = {
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

struct cmdline {
    bool show_help;
    const char *eif_path;
};

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    int c, option_index = 0;

    assert(cmdline != NULL);

    // set the defaults
    *cmdline = (struct cmdline){
        .show_help = false,
        .eif_path = NULL,
    };

    // the '+' in optstring is a GNU extension that disables permutating argv
    while ((c = getopt_long(argc, argv, "+h", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmdline->show_help = true;
            return true;
        case '?':
            return false;
        default:
            fprintf(stderr, "internal argument parsing error (returned character code 0x%x)\n", c);
            return false;
        }
    }

    if (optind < argc) {
        cmdline->eif_path = argv[optind];
        return true;
    } else
        fprintf(stderr, "Missing EIF_FILE argument");

    return false;
}

void *listen_enclave_output(void *opaque)
{
    int ret, fd = (int) opaque, sock, len;
    char buf[512];
    struct sockaddr_un client_sockaddr;

    sock = accept(fd, (struct sockaddr *) &client_sockaddr, &len);
    if (sock < 1)
        return (void *) -1;

    for (;;) {
        ret = read(sock, &buf, 512);
        if (ret <= 0)
            break;
        else if (ret < 512) {
            buf[ret] = '\0';
        }

        printf("%s", buf);
    }
}

int main(int argc, char *const argv[])
{
    int ret, ctx_id, err, i, sock_fd, enable = 1;
    struct cmdline cmdline;
    struct sockaddr_un addr;
    pthread_t thread;

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

    // Configure the number of vCPUs (1) and the amount of RAM (512 MiB).
    if (err = krun_set_vm_config(ctx_id, 1, 512)) {
        errno = -err;
        perror("Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    // Set the nitro enclave image specified on the command line.
    if (err = krun_nitro_set_image(ctx_id, cmdline.eif_path,
                                   KRUN_NITRO_IMG_TYPE_EIF)) {
        errno = -err;
        perror("Error configuring nitro enclave image");
        return -1;

    }

    // Configure the nitro enclave to run in debug mode.
    if (err = krun_nitro_set_start_flags(ctx_id, KRUN_NITRO_START_FLAG_DEBUG)) {
        errno = -err;
        perror("Error configuring nitro enclave start flags");
        return -1;
    }

    // Create and initialize UNIX IPC socket for reading enclave output.
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("Error creating UNIX IPC socket for enclave communication");
        return -1;
    }
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, IPC_SOCK_PATH);

    // Listen on the socket for enclave output.
    unlink(IPC_SOCK_PATH);
    ret = bind(sock_fd, (struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
        perror("Error binding socket");
        close(sock_fd);
        exit(1);
    }

    ret = listen(sock_fd, 1);
    if (ret < 0) {
        perror("Error listening on socket");
        close(sock_fd);
        exit(1);
    }

    // Configure the IPC socket to read output from the enclave. The "port"
    // argument is ignored.
    if (err = krun_add_vsock_port(ctx_id, 0, IPC_SOCK_PATH)) {
        close(sock_fd);
        errno = -err;
        perror("Error configuring enclave vsock");
        return -1;
    }

    ret = pthread_create(&thread, NULL, listen_enclave_output,
                         (void *) sock_fd);
    if (ret < 0) {
        perror("unable to create new listener thread");
        close(sock_fd);
        exit(1);
    }

    // Start and enter the microVM. Unless there is some error while creating the microVM
    // this function never returns.
    if (err = krun_start_enter(ctx_id)) {
        close(sock_fd);
        errno = -err;
        perror("Error creating the microVM");
        return -1;
    }

    ret = pthread_join(thread, NULL);
    if (ret < 0) {
        perror("unable to join listener thread");
        close(sock_fd);
        exit(1);
    }

    return 0;
}

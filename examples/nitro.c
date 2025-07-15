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
#include <sys/time.h>
#include <sys/un.h>
#include <linux/vm_sockets.h>
#include <libkrun.h>
#include <getopt.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>

#define MAX_ARGS_LEN 4096
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

#define VMADDR_CID_HYPERVISOR 0
#define CID_TO_CONSOLE_PORT_OFFSET 10000

#define BUFSIZE 512

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
    socklen_t addr_sz = sizeof(struct sockaddr_vm);
    struct sockaddr_vm addr;
    int ret, sock_fd, cid;
    struct timeval timeval;
    char buf[BUFSIZE];

    cid = (int) opaque;

    sock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock_fd < 0)
        return (void *) -1;

    bzero((char *) &addr, sizeof(struct sockaddr_vm));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_HYPERVISOR;
    addr.svm_port = cid + CID_TO_CONSOLE_PORT_OFFSET;

    // Set vsock timeout limit to 5 seconds.
    memset(&timeval, 0, sizeof(struct timeval));
    timeval.tv_sec = 5;

    ret = setsockopt(sock_fd, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
                        (void *) &timeval, sizeof(struct timeval));
    if (ret < 0) {
        close(sock_fd);
        return (void *) -1;
    }

    ret = connect(sock_fd, (struct sockaddr *) &addr, addr_sz);
    if (ret < 0) {
        close(sock_fd);
        return (void *) -1;
    }

    bzero(buf, BUFSIZE);
    for (;;) {
        ret = read(sock_fd, &buf, BUFSIZE);
        if (ret <= 0)
            break;

        buf[ret] = '\0';

        printf("%s", buf);
    }
}

int main(int argc, char *const argv[])
{
    int ret, cid, ctx_id, err;
    struct cmdline cmdline;
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

    /*
     * Start and enter the microVM. In the libkrun-nitro flavor, a positive
     * value returned by krun_start_enter() is the enclave's CID.
     */
    cid = krun_start_enter(ctx_id);
    if (cid < 0) {
        errno = -err;
        perror("Error creating the microVM");
        return -1;
    }

    ret = pthread_create(&thread, NULL, listen_enclave_output, (void *) cid);
    if (ret < 0) {
        perror("unable to create new listener thread");
        exit(1);
    }

    ret = pthread_join(thread, NULL);
    if (ret < 0) {
        perror("unable to join listener thread");
        exit(1);
    }

    return 0;
}

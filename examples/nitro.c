/*
 * This is an example implementing running an example AWS nitro enclave with
 * libkrun.
 *
 * Given a nitro enclave image, run the image in a nitro enclave with 1 vCPU and
 * 256 MiB of memory allocated.
 */

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
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

int main(int argc, char *const argv[])
{
    int ctx_id, err, i;
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

    // Start and enter the microVM. Unless there is some error while creating the microVM
    // this function never returns.
    if (err = krun_start_enter(ctx_id)) {
        errno = -err;
        perror("Error creating the microVM");
        return -1;
    }

    return 0;
}

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

enum net_mode {
    NET_MODE_PASST = 0,
    NET_MODE_TSI,
};

static void print_help(char *const name)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] NEWROOT COMMAND [COMMAND_ARGS...]\n"
        "OPTIONS: \n"
        "        -h    --help            Show help\n"
        "              --net=NET_MODE    Set network mode\n"
        "NET_MODE can be either TSI (default) or PASST\n"
        "\n"
        "NEWROOT:      the root directory of the vm\n"
        "COMMAND:      the command you want to execute in the vm\n"
        "COMMAND_ARGS: arguments of COMMAND\n",
        name
    );
}

static const struct option long_options[] = {
    { "help", no_argument, NULL, 'h' },
    { "net_mode", required_argument, NULL, 'N' },
    { NULL, 0, NULL, 0 }
};

struct cmdline {
    bool show_help;
    enum net_mode net_mode;
    char const *new_root;
    char *const *guest_argv;
};

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    assert(cmdline != NULL);

    // set the defaults
    *cmdline = (struct cmdline){
        .show_help = false,
        .net_mode = NET_MODE_TSI,
        .new_root = NULL,
        .guest_argv = NULL,
    };

    int option_index = 0;
    int c;
    // the '+' in optstring is a GNU extension that disables permutating argv
    while ((c = getopt_long(argc, argv, "+h", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmdline->show_help = true;
            return true;
        case 'N':
            if (strcasecmp("TSI", optarg) == 0) {
                cmdline->net_mode = NET_MODE_TSI;
            } else if(strcasecmp("PASST", optarg) == 0) {
                cmdline->net_mode = NET_MODE_PASST;
            } else {
                fprintf(stderr, "Unknown mode %s\n", optarg);
                return false;
            }
            break;
        case '?':
            return false;
        default:
            fprintf(stderr, "internal argument parsing error (returned character code 0x%x)\n", c);
            return false;
        }
    }

    if (optind <= argc - 2) {
        cmdline->new_root = argv[optind];
        cmdline->guest_argv = &argv[optind + 1];
        return true;
    }

    if (optind >= argc - 1) {
        fprintf(stderr, "Missing COMMAND argument\n");
    }

    if (optind == argc) {
        fprintf(stderr, "Missing NEWROOT argument\n");
    }

    return false;
}

int connect_to_passt()
{
    struct sockaddr_un addr;
    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("Failed to create passt socket fd");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/passt_1.socket", sizeof(addr.sun_path) - 1);

    if (connect(socket_fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Failed to bind passt socket");
        return -1;
    }

    return socket_fd;
}


int main(int argc, char *const argv[])
{
    char *const envp[] =
    {
        "TEST=works",
        0
    };
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
    char *mapped_volumes[2];
    char current_path[MAX_PATH];
    char volume_tail[] = ":/work\0";
    char *volume;
    int volume_len;
    int ctx_id;
    int err;
    int i;
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

    if (err = krun_set_root(ctx_id, cmdline.new_root)) {
        errno = -err;
        perror("Error configuring root path");
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

    snprintf(volume, volume_len, "%s%s", current_path, volume_tail);
    mapped_volumes[0] = volume;
    mapped_volumes[1] = 0;

    // Map "/tmp" as "/work" inside the VM.
    if (err = krun_set_mapped_volumes(ctx_id, &mapped_volumes[0])) {
        errno = -err;
        perror("Error configuring mapped volumes");
        return -1;
    }

    // Map port 18000 in the host to 8000 in the guest (if networking uses TSI)
    if (cmdline.net_mode == NET_MODE_TSI) {
        if (err = krun_set_port_map(ctx_id, &port_map[0])) {
            errno = -err;
            perror("Error configuring port map");
            return -1;
        }
    } else {
        int passt_fd = connect_to_passt();
        if (passt_fd < 0) {
            return -1;
        }

        if (err = krun_set_passt_fd(ctx_id, passt_fd)) {
            errno = -err;
            perror("Error configuring net mode");
            return -1;
        }
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

    // Specify the path of the binary to be executed in the isolated context, relative to the root path.
    if (err = krun_set_exec(ctx_id, cmdline.guest_argv[0], &cmdline.guest_argv[1], &envp[0])) {
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

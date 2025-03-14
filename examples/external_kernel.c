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

enum net_mode
{
    NET_MODE_PASST = 0,
    NET_MODE_TSI,
};

#if defined(__x86_64__)
#define KERNEL_FORMAT KRUN_KERNEL_FORMAT_ELF
#else
#define KERNEL_FORMAT KRUN_KERNEL_FORMAT_RAW
#endif

static void print_help(char *const name)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS] KERNEL\n"
            "OPTIONS: \n"
            "        -b    --boot-disk           Path to a boot disk in raw format\n"
            "        -c    --kernel-cmdline      Kernel command line\n"
            "        -d    --data-disk           Path to a data disk in raw format\n"
            "        -h    --help                Show help\n"
            "        -i    --initrd              Path to initramfs\n"
            "              --net=NET_MODE        Set network mode\n"
            "              --passt-socket=PATH   Connect to passt socket at PATH"
            "\n"
            "NET_MODE can be either TSI (default) or PASST\n"
            "\n"
#if defined(__x86_64__)
            "KERNEL:   path to the kernel image in ELF format\n",
#else
            "KERNEL:   path to the kernel image in RAW format\n",
#endif
            name);
}

static const struct option long_options[] = {
    {"boot-disk", required_argument, NULL, 'b'},
    {"kernel-cmdline", required_argument, NULL, 'c'},
    {"data-disk", required_argument, NULL, 'd'},
    {"initrd-path", required_argument, NULL, 'i'},
    {"help", no_argument, NULL, 'h'},
    {"passt-socket", required_argument, NULL, 'P'},
    {NULL, 0, NULL, 0}};

struct cmdline
{
    bool show_help;
    enum net_mode net_mode;
    char const *boot_disk;
    char const *data_disk;
    char const *passt_socket_path;
    char const *kernel_path;
    char const *kernel_cmdline;
    char const *initrd_path;
};

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    assert(cmdline != NULL);

    // set the defaults
    *cmdline = (struct cmdline){
        .show_help = false,
        .net_mode = NET_MODE_TSI,
        .passt_socket_path = "/tmp/network.sock",
        .boot_disk = NULL,
        .data_disk = NULL,
        .kernel_path = NULL,
        .kernel_cmdline = NULL,
        .initrd_path = NULL,
    };

    int option_index = 0;
    int c;
    // the '+' in optstring is a GNU extension that disables permutating argv
    while ((c = getopt_long(argc, argv, "+hb:c:d:i:", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'b':
            cmdline->boot_disk = optarg;
            break;
        case 'c':
            cmdline->kernel_cmdline = optarg;
            break;
        case 'd':
            cmdline->data_disk = optarg;
            break;
        case 'h':
            cmdline->show_help = true;
            return true;
        case 'i':
            cmdline->initrd_path = optarg;
            break;
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

    if (optind <= argc - 1)
    {
        cmdline->kernel_path = argv[optind];
        return true;
    }

    if (optind == argc)
    {
        fprintf(stderr, "Missing KERNEL argument\n");
    }

    return false;
}

int connect_to_passt(char *socket_path)
{
    struct sockaddr_un addr;
    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        perror("Failed to create passt socket fd");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(socket_fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Failed to bind passt socket");
        return -1;
    }

    return socket_fd;
}

int start_passt()
{
    int socket_fds[2];
    const int PARENT = 0;
    const int CHILD = 1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds) < 0)
    {
        perror("Failed to create passt socket fd");
        return -1;
    }

    int pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return -1;
    }

    if (pid == 0)
    { // child
        if (close(socket_fds[PARENT]) < 0)
        {
            perror("close PARENT");
        }

        char fd_as_str[16];
        snprintf(fd_as_str, sizeof(fd_as_str), "%d", socket_fds[CHILD]);

        printf("passing fd %s to passt", fd_as_str);

        if (execlp("passt", "passt", "-f", "--fd", fd_as_str, NULL) < 0)
        {
            perror("execlp");
            return -1;
        }
    }
    else
    { // parent
        if (close(socket_fds[CHILD]) < 0)
        {
            perror("close CHILD");
        }

        return socket_fds[PARENT];
    }
}

int main(int argc, char *const argv[])
{
    int ctx_id;
    int err;
    pthread_t thread;
    struct cmdline cmdline;

    if (!parse_cmdline(argc, argv, &cmdline))
    {
        putchar('\n');
        print_help(argv[0]);
        return -1;
    }

    if (cmdline.show_help)
    {
        print_help(argv[0]);
        return 0;
    }

    // Set the log level to "off".
    err = krun_set_log_level(0);
    if (err)
    {
        errno = -err;
        perror("Error configuring log level");
        return -1;
    }

    // Create the configuration context.
    ctx_id = krun_create_ctx();
    if (ctx_id < 0)
    {
        errno = -ctx_id;
        perror("Error creating configuration context");
        return -1;
    }

    // Configure the number of vCPUs (2) and the amount of RAM (1024 MiB).
    if (err = krun_set_vm_config(ctx_id, 2, 2048))
    {
        errno = -err;
        perror("Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    if (cmdline.boot_disk)
    {
        if (err = krun_add_disk(ctx_id, "boot", cmdline.boot_disk, 0))
        {
            errno = -err,
            perror("Error configuring boot disk");
            return -1;
        }
    }
    if (cmdline.data_disk)
    {
        if (err = krun_add_disk(ctx_id, "data", cmdline.data_disk, 0))
        {
            errno = -err,
            perror("Error configuring data disk");
            return -1;
        }
    }

    if (cmdline.net_mode == NET_MODE_PASST)
    {
        int passt_fd = cmdline.passt_socket_path ? connect_to_passt(cmdline.passt_socket_path) : start_passt();

        if (passt_fd < 0)
        {
            return -1;
        }

        if (err = krun_set_passt_fd(ctx_id, passt_fd))
        {
            errno = -err;
            perror("Error configuring net mode");
            return -1;
        }
    }

    fprintf(stderr, "kernel_path: %s\n", cmdline.kernel_path);
    fprintf(stderr, "kernel_cmdline: %s\n", cmdline.kernel_cmdline);
    fflush(stderr);

    if (err = krun_set_kernel(ctx_id, cmdline.kernel_path, KERNEL_FORMAT,
                              cmdline.initrd_path, cmdline.kernel_cmdline))
    {
        errno = -err;
        perror("Error configuring kernel");
        return -1;
    }

    // Start and enter the microVM. Unless there is some error while creating the microVM
    // this function never returns.
    if (err = krun_start_enter(ctx_id))
    {
        errno = -err;
        perror("Error creating the microVM");
        return -1;
    }

    // Not reached.
    return 0;
}

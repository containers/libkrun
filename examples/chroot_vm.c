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
#include <sys/resource.h>
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

// TODO: autodetect
#if defined(__x86_64__)
#define KERNEL_FORMAT KRUN_KERNEL_FORMAT_ELF
#else
#define KERNEL_FORMAT KRUN_KERNEL_FORMAT_RAW
#endif

static void print_help(char *const name)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] NEWROOT COMMAND [COMMAND_ARGS...]\n"
        "OPTIONS: \n"
        "        -h    --help                Show help\n"
        "              --net=NET_MODE        Set network mode\n"
        "              --passt-socket=PATH   Instead of starting passt, connect to passt socket at PATH"
        "NET_MODE can be either TSI (default) or PASST\n"
        "              --kernel              Path for loading a kernel in place of one supplied by libkrunfw\n"
        "              --kernel-cmdline      Cmdline for externally-loaded kernel\n"
        "              --initrd-path         Initrd for externally-loaded kernel (optional)\n"
        "              --boot-disk           Add a boot disk (virtio-blk)\n"
        "              --data-disk           Add a data disk (virtio-blk)\n"
        "\n"
        "NEWROOT:      the root directory of the vm (virtio-fs)\n"
        "COMMAND:      the command you want to execute in the vm\n"
        "COMMAND_ARGS: arguments of COMMAND\n",
        name
    );
}

static const struct option long_options[] = {
    { "help", no_argument, NULL, 'h' },
    { "net_mode", required_argument, NULL, 'N' },
    { "passt-socket", required_argument, NULL, 'P' },
    { "kernel", required_argument, NULL, 'k'},
    { "kernel-cmdline", required_argument, NULL, 'c'},
    { "initrd-path", required_argument, NULL, 'i'},
    { "boot-disk", required_argument, NULL, 'b'},
    { "data-disk", required_argument, NULL, 'd'},
    { NULL, 0, NULL, 0 }
};

struct cmdline {
    bool show_help;
    enum net_mode net_mode;
    char const *passt_socket_path;
    char const *new_root;
    char *const *guest_argv;
    char const *boot_disk;
    char const *data_disk;
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
        .passt_socket_path = NULL,
        .new_root = NULL,
        .guest_argv = NULL,
        .kernel_path = NULL,
        .kernel_cmdline = NULL,
        .initrd_path = NULL,
        .boot_disk = NULL,
        .data_disk = NULL,
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
        case 'P':
            cmdline->passt_socket_path = optarg;
            break;
        case 'k':
            cmdline->kernel_path = optarg;
            break;
        case 'c':
            cmdline->kernel_cmdline = optarg;
            break;
        case 'i':
            cmdline->initrd_path = optarg;
            break;
        case 'b':
            cmdline->boot_disk = optarg;
            break;
        case 'd':
            cmdline->data_disk = optarg;
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

    // User must either supply rootfs and command or boot disk
    if (cmdline->boot_disk) {
        return true;
    }

    if (optind >= argc - 1) {
        fprintf(stderr, "Missing COMMAND argument, but no boot disk has been specified\n");
    }

    if (optind == argc) {
        fprintf(stderr, "Missing NEWROOT argument, but no boot disk has been specified\n");
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

int start_passt()
{
    int socket_fds[2];
    const int PARENT = 0;
    const int CHILD = 1;
    
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds) < 0) {
        perror("Failed to create passt socket fd");
        return -1;
    }

    int pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    
    if (pid == 0) { // child
        if (close(socket_fds[PARENT]) < 0) {
            perror("close PARENT");
        }

        char fd_as_str[16]; 
        snprintf(fd_as_str, sizeof(fd_as_str), "%d", socket_fds[CHILD]);

        printf("passing fd %s to passt", fd_as_str);

        if (execlp("passt", "passt", "-f", "--fd", fd_as_str, NULL) < 0) {
            perror("execlp");
            return -1;
        }

    } else { // parent
        if (close(socket_fds[CHILD]) < 0) {
            perror("close CHILD");
        }

        return socket_fds[PARENT];
    }
}


int main(int argc, char *const argv[])
{
    const char *const envp[] =
    {
        "TEST=works",
        0
    };
    const char *const port_map[] =
    {
        "18000:8000",
        0
    };
    const char *const rlimits[] =
    {
        // RLIMIT_NPROC = 6
        "6=4096:8192",
        0
    };
    int ctx_id;
    int err;
    int i;
    struct cmdline cmdline;
    struct rlimit rlim;

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
    if (err = krun_set_vm_config(ctx_id, 4, 4096)) {
        errno = -err;
        perror("Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    // Raise RLIMIT_NOFILE to the maximum allowed to create some room for virtio-fs
    getrlimit(RLIMIT_NOFILE, &rlim);
    rlim.rlim_cur = rlim.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rlim);

    if (cmdline.boot_disk && (err = krun_add_disk(ctx_id, "boot", cmdline.boot_disk, 0))) {
        errno = -err,
        perror("Error configuring boot disk");
        return -1;
    }
    if (cmdline.data_disk && (err = krun_add_disk(ctx_id, "data", cmdline.data_disk, 0))) {
        errno = -err,
        perror("Error configuring data disk");
        return -1;
    }

    if (cmdline.new_root && (err = krun_set_root(ctx_id, cmdline.new_root))) {
        errno = -err;
        perror("Error configuring root path");
        return -1;
    }

    uint32_t virgl_flags = VIRGLRENDERER_USE_EGL | VIRGLRENDERER_DRM |
	    VIRGLRENDERER_THREAD_SYNC | VIRGLRENDERER_USE_ASYNC_FENCE_CB;
    if (err = krun_set_gpu_options(ctx_id, virgl_flags)) {
        errno = -err;
        perror("Error configuring gpu");
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
        int passt_fd = cmdline.passt_socket_path ? connect_to_passt(cmdline.passt_socket_path) : start_passt();

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
    if (cmdline.guest_argv && (err = krun_set_exec(ctx_id, cmdline.guest_argv[0], (const char* const*) &cmdline.guest_argv[1], &envp[0]))) {
        errno = -err;
        perror("Error configuring the parameters for the executable to be run");
        return -1;
    }

    if (cmdline.kernel_path &&
        (err = krun_set_kernel(ctx_id, cmdline.kernel_path, KERNEL_FORMAT,
        cmdline.initrd_path, cmdline.kernel_cmdline)))
    {
        errno = -err;
        perror("Error configuring kernel");
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

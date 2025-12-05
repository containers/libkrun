/*
 * This is an example implementing running an example AWS nitro enclave with
 * libkrun.
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
        "Usage: %s ENCLAVE_IMAGE NEWROOT NVCPUS RAM_MIB\n"
        "OPTIONS: \n"
        "        -h    --help                Show help\n"
        "              --net                 Enable networking with passt"
        "\n"
        "NEWROOT:           The root directory of the VM\n"
        "NVCPUS:            The amount of vCPUs for running the enclave\n"
        "RAM_MIB:           The amount of RAM (MiB) allocated for enclave\n",
        name
    );
}

static const struct option long_options[] = {
    { "help", no_argument, NULL, 'h' },
    { "net", no_argument, NULL, 'n' },
    { NULL, 0, NULL, 0 }
};

struct cmdline {
    bool show_help;
    const char *new_root;
    unsigned int nvcpus;
    unsigned int ram_mib;
    bool net;
};

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    int c, option_index = 0;

    assert(cmdline != NULL);

    // set the defaults
    *cmdline = (struct cmdline){
        .show_help = false,
        .net = false,
    };

    // the '+' in optstring is a GNU extension that disables permutating argv
    while ((c = getopt_long(argc, argv, "+h", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmdline->show_help = true;
            return true;
        case 'n':
            cmdline->net = true;
            break;
        case '?':
            return false;
        default:
            fprintf(stderr, "internal argument parsing error (returned character code 0x%x)\n", c);
            return false;
        }
    }

    if (optind < argc - 2) {
        cmdline->new_root = argv[optind];
        cmdline->nvcpus = strtoul(argv[optind + 1], NULL, 10);
        cmdline->ram_mib = strtoul(argv[optind + 2], NULL, 10);
        return true;
    }

    if (optind >= argc - 2)
        fprintf(stderr, "Missing RAM_MIB argument\n");
    if (optind >= argc - 1)
        fprintf(stderr, "Missing VCPUS argument\n");
    if (optind == argc)
        fprintf(stderr, "Missing NEWROOT argument\n");

    return false;
}

void *listen_enclave_app_output(void *opague)
{
    int ret, sock_fd, bytes_read, client_fd;
    char buffer[BUFSIZE];
    struct sockaddr_vm addr;
    struct timeval timeval;

    sock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("unable to create host socket for application output");
        return (void *)-1;
    }

    bzero((char *) &addr, sizeof(struct sockaddr_vm));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_ANY;
    addr.svm_port = 8081;

    memset(&timeval, 0, sizeof(struct timeval));
    timeval.tv_sec = 5;

    ret = setsockopt(sock_fd, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT, (void *) &timeval, sizeof(struct timeval));
    if (ret < 0) {
        close(sock_fd);
        perror("unable to set socket options for application output socket");
        return (void *)-1;
    }

    ret = bind(sock_fd, (struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
        close(sock_fd);
        perror("unable to bind the host application output socket to the address");
        return (void *)-1;
    }

    ret = listen(sock_fd, 1);
    if (ret < 0) {
        close(sock_fd);
        perror("unable to listen for incoming connection to host application output socket.");
        return (void *)-1;
    }

    client_fd = accept(sock_fd, NULL, NULL);
    if (client_fd < 0) {
        close(sock_fd);
        perror("unable to connect host application output socket to guest socket");
        return (void *)-1;
    }

    close(sock_fd);

    while((bytes_read = read(client_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
        fflush(stdout);
    }

    if (bytes_read < 0)
        perror("application output socket read error");

    close(client_fd);
    return (void *)0;
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

const char *const default_argv[] = { "cat", "/etc/os-release", NULL };

#define DEFAULT_PATH_ENV "PATH=/sbin:/usr/sbin:/bin:/usr/bin"
const char *const default_envp[] = {
    DEFAULT_PATH_ENV,
    NULL,
};

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
    int ret, cid, ctx_id, err, passt_fd;
    struct cmdline cmdline;
    pthread_t debug_console_thread, app_thread;

    int nitro_start_flags = KRUN_NITRO_START_FLAG_DEBUG;

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
    err = krun_init_log(KRUN_LOG_TARGET_DEFAULT, KRUN_LOG_LEVEL_OFF, KRUN_LOG_STYLE_AUTO, 0);
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

    // Configure the number of vCPUs and amount of RAM.
    if (err = krun_set_vm_config(ctx_id, cmdline.nvcpus, cmdline.ram_mib)) {
        errno = -err;
        perror("Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    // Configure the nitro enclave to run in debug mode.
    if (err = krun_nitro_set_start_flags(ctx_id, nitro_start_flags)) {
        errno = -err;
        perror("Error configuring nitro enclave start flags");
        return -1;
    }

    // Configure the enclave's rootfs.
    if (err = krun_set_root(ctx_id, cmdline.new_root)) {
        errno = -err;
        perror("Error configuring enclave rootfs");
        return -1;
    }

    // Configure the enclave's execution environment.
    if (err = krun_set_exec(ctx_id, "ls", default_argv, default_envp)) {
        errno = -err;
        perror("Error configuring enclave execution path");
        return -1;
    }

    if (cmdline.net) {
        uint8_t mac[] = { 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee };

        passt_fd = start_passt();
        if (passt_fd < 0) {
            printf("unable to start passt socket pair\n");
            return -1;
        }

        if (err = krun_add_net_unixstream(ctx_id, NULL, passt_fd, &mac[0], COMPAT_NET_FEATURES, 0)) {
            errno = -err;
            perror("Error configuring net mode");
            return -1;
        }
    }

    ret = pthread_create(&app_thread, NULL, listen_enclave_app_output, NULL);
    if (ret < 0) {
        perror("unable to create new app listener thread");
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

    if (nitro_start_flags == KRUN_NITRO_START_FLAG_DEBUG) {
        ret = pthread_create(&debug_console_thread, NULL, listen_enclave_output, (void *) cid);
        if (ret < 0) {
            perror("unable to create new listener thread");
            return -1;
        }
    }

    ret = pthread_join(app_thread, NULL);
    if (ret < 0) {
        perror("unable to join app listener thread");
        return -1;
    }
    return 0;
}

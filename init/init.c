#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/vm_sockets.h>

#include "utils.h"

#define KRUN_REMOVE_ROOT_DIR_IOCTL 0x7603

char DEFAULT_KRUN_INIT[] = "/bin/sh";

int main(int argc, char **argv)
{
    struct ifreq ifr;
    int fd;
    int sockfd;
    int status;
    int saved_errno;
    bool init_pid1 = false;
    char localhost[] = "localhost\0";
    char *hostname;
    char *krun_home;
    char *krun_term;
    char *krun_init;
    char *krun_root;
    char *krun_root_fstype;
    char *krun_root_options;
    char *env_init_pid1;
    char *config_workdir, *env_workdir;
    char *rlimits;
    char **config_argv, **exec_argv;

    if (mount_filesystems() < 0) {
        printf("Couldn't mount filesystems, bailing out\n");
        exit(-2);
    }

    krun_root = getenv("KRUN_BLOCK_ROOT_DEVICE");
    if (krun_root) {
        if (mkdir("/newroot", 0755) < 0 && errno != EEXIST) {
            perror("mkdir(/newroot)");
            exit(-1);
        }

        krun_root_fstype = getenv("KRUN_BLOCK_ROOT_FSTYPE");
        krun_root_options = getenv("KRUN_BLOCK_ROOT_OPTIONS");

        if (try_mount(krun_root, "/newroot", krun_root_fstype, 0,
                      krun_root_options) < 0) {
            perror("mount KRUN_BLOCK_ROOT_DEVICE");
            exit(-1);
        }

        chdir("/newroot");

        fd = open("/", O_RDONLY);
        if (fd < 0) {
            perror("Couldn't open temporary root directory for removing");
            exit(-1);
        }
        if (ioctl(fd, KRUN_REMOVE_ROOT_DIR_IOCTL) < 0) {
            perror("Error removing temporary root directory");
        }
        close(fd);

        if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
            perror("remount root");
            exit(-1);
        }
        chroot(".");

        // we must mount filesystems again after chrooting
        if (mount_filesystems() < 0) {
            printf("Couldn't mount filesystems, bailing out\n");
            exit(-2);
        }
    }

    if (mount(NULL, "/", NULL, MS_REC | MS_SHARED, NULL) < 0) {
        perror("Couldn't set shared propagation on the root mount");
        exit(-1);
    }

    setsid();
    ioctl(0, TIOCSCTTY, 1);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd >= 0) {
        memset(&ifr, 0, sizeof ifr);
        strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
        ifr.ifr_flags |= IFF_UP;
        ioctl(sockfd, SIOCSIFFLAGS, &ifr);
        close(sockfd);
    }

    config_argv = NULL;
    config_workdir = NULL;

    config_parse_file(&config_argv, &config_workdir);

    krun_home = getenv("KRUN_HOME");
    if (krun_home) {
        setenv("HOME", krun_home, 1);
    }

    krun_term = getenv("KRUN_TERM");
    if (krun_term) {
        setenv("TERM", krun_term, 1);
    }

    hostname = getenv("HOSTNAME");
    if (hostname) {
        sethostname(hostname, strlen(hostname));
    } else {
        sethostname(&localhost[0], strlen(localhost));
    }

    rlimits = getenv("KRUN_RLIMITS");
    if (rlimits) {
        set_rlimits(rlimits);
    }

    env_workdir = getenv("KRUN_WORKDIR");
    if (env_workdir) {
        chdir(env_workdir);
    } else if (config_workdir) {
        chdir(config_workdir);
    }

    exec_argv = argv;
    krun_init = getenv("KRUN_INIT");
    if (krun_init) {
        exec_argv[0] = krun_init;
    } else if (config_argv) {
        exec_argv = config_argv;
    } else {
        exec_argv[0] = &DEFAULT_KRUN_INIT[0];
    }

    env_init_pid1 = getenv("KRUN_INIT_PID1");
    if (env_init_pid1 && *env_init_pid1 == '1') {
        init_pid1 = true;
    }

#ifdef __TIMESYNC__
    if (fork() == 0) {
        clock_worker();
        _exit(1);
    }
#endif

    if (init_pid1) {
        goto exec_init;
    }

    // We need to fork ourselves, because pid 1 cannot doesn't receive SIGINT
    // signal
    int child = fork();
    if (child < 0) {
        perror("fork");
        set_exit_code(125);
        exit(125);
    }
    if (child == 0) { // child
    exec_init:
        if (setup_redirects() < 0) {
            exit(125);
        }
        if (execvp(exec_argv[0], exec_argv) < 0) {
            saved_errno = errno;
            printf("Couldn't execute '%s' inside the vm: %s\n", exec_argv[0],
                   strerror(errno));
            // Use the same exit code as chroot and podman do.
            if (saved_errno == ENOENT) {
                exit(127);
            } else {
                exit(126);
            }
        }
    } else { // parent
        // Wait until the workload's entrypoint has exited, ignoring any other
        // children.
        while (waitpid(-1, &status, 0) != child) {
            // Not the first child, ignore it.
        };

        // The workload's entrypoint has exited, record its exit code and exit
        // ourselves.
        if (WIFEXITED(status)) {
            set_exit_code(WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            set_exit_code(WTERMSIG(status) + 128);
        }
    }

    return 0;
}

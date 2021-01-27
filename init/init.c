#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

char DEFAULT_KRUN_INIT[] = "/bin/sh";

int main(int argc, char **argv)
{
    struct ifreq ifr;
    int sockfd;
    char *hostname;
    char *krun_init;
    char *workdir;

    if (mount("proc", "/proc", "proc",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
        perror("mount(/proc): ");
        exit(-1);
    }

    if (mount("sysfs", "/sys", "sysfs",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
        perror("mount(/sys): ");
        exit(-1);
    }

    if (mkdir("/dev/pts", 0755) != 0) {
        perror("mkdir(/dev/pts): ");
        exit(-1);
    }

    if (mount("devpts", "/dev/pts", "devpts",
              MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
        perror("mount(/dev/pts): ");
        exit(-1);
    }

    /* May fail if already exists and that's fine. */
    symlink("/proc/self/fd", "/dev/fd");

    hostname = getenv("HOSTNAME");
    if (hostname) {
        sethostname(hostname, strlen(hostname));
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

    workdir = getenv("KRUN_WORKDIR");
    if (workdir) {
        chdir(workdir);
    }

    krun_init = getenv("KRUN_INIT");
    if (!krun_init) {
        krun_init = &DEFAULT_KRUN_INIT[0];
    }
    argv[0] = krun_init;

    execv(argv[0], argv);

    return 0;
}

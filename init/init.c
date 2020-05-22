#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

char DEFAULT_KIP_INIT[] = "/bin/sh";

int main(int argc, char **argv)
{
    char *hostname;
    char *kip_init;

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

    hostname = getenv("HOSTNAME");
    if (hostname) {
        sethostname(hostname, strlen(hostname));
    }

    setsid();
    ioctl(0, TIOCSCTTY, 1);

    kip_init = getenv("KIP_INIT");
    if (!kip_init) {
        kip_init = &DEFAULT_KIP_INIT[0];
    }
    argv[0] = kip_init;

    unlink("/tmp/vmlinux.kip");
    unlink("/tmp/init.kip");

    execv(argv[0], argv);

    return 0;
}

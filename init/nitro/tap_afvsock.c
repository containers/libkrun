// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/vm_sockets.h>

#include "include/tap_afvsock.h"
#include "include/vsock.h"

#define TUN_DEV_MAJOR 10
#define TUN_DEV_MINOR 200

#define VSOCK_NET_PORT 8080

volatile sig_atomic_t proxy_ready = 0;

static void sig_handler(int sig)
{
    if (sig == SIGUSR1)
        proxy_ready = 1;
}

static int tap_vsock_forward(int tun_fd, int vsock_fd, char *tap_name)
{
    struct pollfd pfds[2];
    unsigned char *buf;
    struct ifreq ifr;
    ssize_t nread;
    int ret, sock_fd;

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("creating INET socket to get TAP MTU");
        return -errno;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, tap_name, IFNAMSIZ);

    ret = ioctl(sock_fd, SIOCGIFMTU, &ifr);
    if (ret < 0) {
        close(sock_fd);
        perror("fetch MTU of TAP device");
        exit(ret);
    }

    close(sock_fd);

    buf = (unsigned char *)malloc(ifr.ifr_mtu);
    if (buf == NULL) {
        perror("allocate buffer for TAP/vsock communication");
        exit(-1);
    }

    pfds[0].fd = vsock_fd;
    pfds[0].events = POLLIN;

    pfds[1].fd = tun_fd;
    pfds[1].events = POLLIN;

    kill(getppid(), SIGUSR1);

    while (poll(pfds, 2, -1) > 0) {
        if (pfds[0].revents & POLLIN) {
            unsigned int sz;
            nread = read(vsock_fd, &sz, 4);
            if (nread != 4)
                exit(0);

            unsigned int len = htonl(sz);

            nread = read(vsock_fd, buf, len);
            write(tun_fd, buf, nread);
        }

        if (pfds[1].revents & POLLIN) {
            nread = read(tun_fd, buf, ifr.ifr_mtu);
            if (nread > 0) {
                unsigned int sz = htonl(nread);
                write(vsock_fd, (void *)&sz, 4);
                write(vsock_fd, buf, nread);
            }
        }
    }

    close(vsock_fd);
    close(tun_fd);

    exit(0);
}

static int tun_init(void)
{
    struct stat statbuf;
    dev_t dev;
    int ret;

    // Check if /dev/net exists.
    ret = stat("/dev/net", &statbuf);
    if (ret < 0 && errno == ENOENT) {
        // Directory doesn't exist, create it.
        ret = mkdir("/dev/net", 0755);
        if (ret < 0) {
            perror("mkdir /dev/net");
            return -errno;
        }
    } else if (ret < 0)
        return -errno;

    // Check if /dev/net/tun exists.
    ret = stat("/dev/net/tun", &statbuf);
    if (ret < 0 && errno == ENOENT) {
        // Node doesn't exist, create it.
        dev = makedev(TUN_DEV_MAJOR, TUN_DEV_MINOR);
        ret = mknod("/dev/net/tun", S_IFCHR, dev);
        if (ret < 0) {
            perror("mknod /dev/net/tun");
            return -errno;
        }
    } else if (ret < 0)
        return -errno;

    /*
     * Allow all users to read/write to /dev/net/tun. Allowing the device to be
     * accessible by non-root users is safe, as CAP_NET_ADMIN is required for
     * connecting to network devices not owned by the user in question.
     */
    ret = chmod("/dev/net/tun", 0666);
    if (ret < 0) {
        perror("chmod /dev/net/tun");
        return -errno;
    }

    return 0;
}

static int tap_assign_ipaddr(char *name)
{
    struct sockaddr_in *addr;
    struct rtentry route;
    struct ifreq ifr;
    int ret, sock_fd;

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("creating IP address configuration socket");
        return -errno;
    }

    // Set the IP address.
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, "10.0.0.1", &addr->sin_addr);

    ret = ioctl(sock_fd, SIOCSIFADDR, &ifr);
    if (ret < 0) {
        close(sock_fd);
        perror("setting TAP IP address");
        return -errno;
    }

    // Set the netmask.
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.0", &addr->sin_addr);

    ret = ioctl(sock_fd, SIOCSIFNETMASK, &ifr);
    if (ret < 0) {
        close(sock_fd);
        perror("setting TAP netmask");
        return -errno;
    }

    // Set the MAC address.
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

    unsigned char mac[] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee};

    memcpy(ifr.ifr_hwaddr.sa_data, &mac[0], 6);

    ret = ioctl(sock_fd, SIOCSIFHWADDR, &ifr);
    if (ret < 0) {
        close(sock_fd);
        perror("setting MAC address");
        return -errno;
    }

    // Set the flags to UP and RUNNING.
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    ret = ioctl(sock_fd, SIOCGIFFLAGS, &ifr);
    if (ret < 0) {
        close(sock_fd);
        perror("getting TAP flags");
        return -errno;
    }

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    ret = ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
    if (ret < 0) {
        close(sock_fd);
        perror("setting TAP flags");
        return -errno;
    }

    // Set the default gateway to the TAP device.
    memset(&route, 0, sizeof(struct rtentry));

    // Set the gateway IP.
    addr = (struct sockaddr_in *)&route.rt_gateway;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr("10.0.0.1");

    // Set the destination to 0.0.0.0 (default route).
    addr = (struct sockaddr_in *)&route.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    // Set the genmask to 0.0.0.0.
    addr = (struct sockaddr_in *)&route.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    // Set the flags to UP and GATEWAY for default gateway.
    route.rt_flags = RTF_UP | RTF_GATEWAY;

    // Set the interface.
    route.rt_dev = ifr.ifr_name;

    ret = ioctl(sock_fd, SIOCADDRT, &route);
    if (ret < 0) {
        close(sock_fd);
        perror("setting default gateway to TAP device");
        return -errno;
    }

    close(sock_fd);

    return 0;
}

static int tap_alloc(char *name)
{
    struct ifreq ifr;
    int ret, fd;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        return -errno;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    ret = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (ret < 0) {
        perror("error setting ifreq for TAP device");
        return -errno;
    }

    strcpy(name, ifr.ifr_name);

    ret = tap_assign_ipaddr(name);
    if (ret < 0)
        return ret;

    return fd;
}

int tap_afvsock_init(void)
{
    int ret, tun_fd, vsock_fd;
    struct sockaddr_vm saddr;
    char tap_name[IFNAMSIZ];
    struct timeval timeval;
    struct sigaction sa;
    pid_t pid;

    // Ensure that /dev/net/tun is initialized. If not, initialize the device.
    ret = tun_init();
    if (ret < 0)
        return ret;

    // Initialize the TAP device.
    strcpy(tap_name, "tap0");
    tun_fd = tap_alloc(tap_name);
    if (ret < 0)
        return ret;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL);

    ret = sigaction(SIGUSR1, &sa, NULL);
    if (ret < 0) {
        perror("sigaction");
        return -errno;
    }

    pid = fork();
    switch (pid) {
    case -1:
        perror("network proxy process");
        exit(EXIT_FAILURE);
    case 0:
        vsock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        if (vsock_fd < 0) {
            perror("network vsock creation");
            return -errno;
        }

        memset(&timeval, 0, sizeof(struct timeval));
        timeval.tv_sec = 5;
        ret = setsockopt(vsock_fd, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT,
                         (void *)&timeval, sizeof(struct timeval));
        if (ret < 0) {
            perror("set network proxy socket timeout");
            return -errno;
        }

        // Initialize the vsock used for network proxying.
        memset(&saddr, 0, sizeof(struct sockaddr_vm));
        saddr.svm_family = AF_VSOCK;
        saddr.svm_cid = VMADDR_CID_HOST;
        saddr.svm_port = VSOCK_NET_PORT;
        saddr.svm_reserved1 = 0;

        ret = connect(vsock_fd, (struct sockaddr *)&saddr, sizeof(saddr));
        if (ret < 0) {
            perror("vsock connect");
            exit(EXIT_FAILURE);
        }

        ret = tap_vsock_forward(tun_fd, vsock_fd, tap_name);
        if (ret < 0)
            exit(EXIT_FAILURE);
    default:
        while (!proxy_ready)
            ;
    }

    return 0;
}

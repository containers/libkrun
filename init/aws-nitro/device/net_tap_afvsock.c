// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
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

#include "include/device.h"

#define TUN_DEV_MAJOR 10
#define TUN_DEV_MINOR 200

/*
 * The Extended Ethernet Frame header is 14 bytes, representing the Destination
 * Address (6 bytes), Source Address (6 bytes) and the Ethertype (2 bytes).
 */
#define ETH_HEADER_LEN 14

#define PROXY_HEADER_LEN 4

/*
 * Read exactly n bytes into the buffer, retrying on partial reads.
 * Returns n on success, 0 on clean EOF, or -1 on error.
 */
static ssize_t read_exact(int fd, void *buf, size_t num_bytes)
{
    ssize_t total = 0;
    ssize_t bytes_read;

    while (total < num_bytes) {
        bytes_read = read(fd, (char *)buf + total, num_bytes - total);
        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (bytes_read == 0)
            return (total > 0) ? -1 : 0;
        total += bytes_read;
    }
    return total;
}

/*
 * Write exactly n bytes from the buffer to the fd, retrying on partial writes.
 * Returns n on success, or -1 on error.
 */
static ssize_t write_all(int fd, const void *buf, size_t num_bytes)
{
    ssize_t total = 0;
    ssize_t bytes_written;

    while (total < num_bytes) {
        bytes_written = write(fd, (const char *)buf + total, num_bytes - total);
        if (bytes_written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        total += bytes_written;
    }
    return total;
}

/*
 * Forward ethernet packets to/from the host vsock providing network access and
 * the guest TAP device routing application network traffic.
 */
static int tap_vsock_forward(int tun_fd, int vsock_fd, int shutdown_fd,
                             char *tap_name)
{
    struct pollfd pfds[3];
    unsigned char *buf;
    bool event_found;
    struct ifreq ifr;
    int ret, sock_fd;
    uint32_t sz;
    ssize_t nread;

    /*
     * Fetch the TAP device's Maximum Transfer Unit (MTU) and allocate a buffer
     * in that size to transfer ethernet frames to/from the host.
     */
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("creating INET socket to get TAP MTU");
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, tap_name, IFNAMSIZ);

    ret = ioctl(sock_fd, SIOCGIFMTU, &ifr);
    if (ret < 0) {
        close(sock_fd);
        perror("fetch MTU of TAP device");
        return -1;
    }

    close(sock_fd);

    uint32_t eth_frame_size = ifr.ifr_mtu + ETH_HEADER_LEN;
    buf = (unsigned char *)malloc(eth_frame_size);
    if (buf == NULL) {
        perror("allocate buffer for TAP/vsock communication");
        return -1;
    }

    // Forward the max ethernet frame size to the host for it to allocate a
    // corresponding buffer.

    // To avoid issues where the host endianness and the enclave endianness is
    // different, convert to big endian to pass the max ethernet frame size to
    // the host.
    uint32_t eth_frame_size_be = htonl(eth_frame_size);
    ret = write_all(vsock_fd, &eth_frame_size_be, sizeof(eth_frame_size));
    if (ret < 0) {
        perror("write max ethernet frame size to host");
        goto cleanup;
    }

    pfds[0].fd = vsock_fd;
    pfds[0].events = POLLIN;

    pfds[1].fd = tun_fd;
    pfds[1].events = POLLIN;

    pfds[2].fd = shutdown_fd;
    pfds[2].events = POLLIN;

    // Signal to the parent process that initialization is complete.
    kill(getppid(), SIGUSR1);

    while (1) {
        ret = poll(pfds, 3, -1);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            perror("poll on TAP/vsock proxy descriptors");
            goto cleanup;
        }
        if (ret == 0)
            continue;

        event_found = false;
        // Event on vsock. Read the frame and write it to the TAP device.
        if (pfds[0].revents & POLLIN) {
            nread = read_exact(vsock_fd, &sz, PROXY_HEADER_LEN);
            if (nread == 0) {
                // vsock connection closed cleanly
                break;
            } else if (nread < 0) {
                perror("unable to read the proxy header from vsock");
                ret = -1;
                goto cleanup;
            }

            uint32_t len = ntohl(sz);
            if (len > eth_frame_size) {
                fprintf(stderr,
                        "ethernet frame size %u exceeds MTU + header size %u\n",
                        len, eth_frame_size);
                ret = -1;
                goto cleanup;
            }

            nread = read_exact(vsock_fd, buf, len);
            if (nread != (ssize_t)len) {
                if (nread == 0)
                    errno = EIO;

                perror("failed to read the ethernet frame from vsock");
                ret = -1;
                goto cleanup;
            }

            // TAP devices are expected to write an entire frame at once and not
            // do partial writes. Only retry if the syscall is interrupted.
            ssize_t bytes_written = 0;
            do {
                bytes_written = write(tun_fd, buf, nread);
            } while (bytes_written < 0 && errno == EINTR);

            if (bytes_written != nread) {
                // the entire frame wasn't written
                if (bytes_written >= 0)
                    errno = EIO;

                perror("unable to write the ethernet frame to the TAP device");
                ret = -1;
                goto cleanup;
            }

            event_found = true;
        }

        // Event on the TAP device. Read the frame and write it to the vsock.
        if (pfds[1].revents & POLLIN) {
            // TAP devices are expected to read an entire frame at once and not
            // do partial reads. Only retry if the syscall is interrupted.
            do {
                nread = read(tun_fd, buf, eth_frame_size);
            } while (nread < 0 && errno == EINTR);
            if (nread <= 0) {
                if (nread == 0)
                    errno = EIO;

                perror("failed to read the ethernet frame from the TAP device");
                ret = -1;
                goto cleanup;
            }

            sz = htonl((uint32_t)nread);
            ret = write_all(vsock_fd, (void *)&sz, PROXY_HEADER_LEN);
            if (ret < 0) {
                perror("unable to write the proxy header to vsock");
                goto cleanup;
            }
            ret = write_all(vsock_fd, buf, nread);
            if (ret < 0) {
                perror("unable to write the ethernet frame to vsock");
                goto cleanup;
            }

            event_found = true;
        }

        if (event_found)
            continue;

        /*
         * No events on network proxy sockets, check shutdown FD and shut down
         * if event found.
         */
        if (pfds[2].revents & POLLIN)
            break;
    }

cleanup:
    free(buf);
    return ret;
}

/*
 * Initialize the enclave TAP device to route all network traffic to the host.
 */
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

/*
 * Assign IP data to route enclave network traffic to the TAP device.
 */
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
    inet_pton(AF_INET, "172.31.10.83", &addr->sin_addr);

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
    addr->sin_addr.s_addr = inet_addr("172.31.10.83");

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

/*
 * Allocate a TAP device for enclave network traffic.
 */
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

    // Assign the IP data to the TAP device.
    ret = tap_assign_ipaddr(name);
    if (ret < 0)
        return ret;

    return fd;
}

/*
 * Initialize a TAP device to route network traffic to/from.
 */
int tap_afvsock_init(unsigned int vsock_port, int shutdown_fd)
{
    int ret, tun_fd, vsock_fd;
    struct sockaddr_vm saddr;
    char tap_name[IFNAMSIZ];
    struct timeval timeval;
    pid_t pid;

    // Ensure that /dev/net/tun is initialized. If not, initialize the device.
    ret = tun_init();
    if (ret < 0)
        return ret;

    // Initialize the TAP device.
    strcpy(tap_name, "tap0");
    tun_fd = tap_alloc(tap_name);
    if (tun_fd < 0)
        return tun_fd;

    pid = fork();
    switch (pid) {
    case -1:
        perror("network proxy process");
        exit(EXIT_FAILURE);
    case 0:
        // Initialize the vsock used for network proxying.
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

        memset(&saddr, 0, sizeof(struct sockaddr_vm));
        saddr.svm_family = AF_VSOCK;
        saddr.svm_cid = VMADDR_CID_HOST;
        saddr.svm_port = vsock_port;
        saddr.svm_reserved1 = 0;

        ret = connect(vsock_fd, (struct sockaddr *)&saddr, sizeof(saddr));
        if (ret < 0) {
            perror("vsock connect");
            exit(EXIT_FAILURE);
        }

        // Forward network traffic between the host and TAP device.
        ret = tap_vsock_forward(tun_fd, vsock_fd, shutdown_fd, tap_name);
        close(vsock_fd);
        close(tun_fd);
        exit(ret < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
    }

    close(tun_fd);
    return 0;
}

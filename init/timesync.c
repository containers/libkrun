#include "timesync.h"

void clock_worker()
{
    int sockfd, n;
    struct sockaddr_vm serveraddr;
    char buf[BUFSIZE];
    struct timespec gtime;
    struct timespec htime;
    uint64_t gtime_ns;
    uint64_t htime_ns;

    sockfd = socket(AF_VSOCK, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Couldn't create timesync socket");
        return;
    }

    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.svm_family = AF_VSOCK;
    serveraddr.svm_port = TSYNC_PORT;
    serveraddr.svm_cid = 3;

    bzero(buf, BUFSIZE);

    n = bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (n < 0) {
        printf("Couldn't bind timesync socket\n");
        return;
    }

    while (1) {
        n = recv(sockfd, buf, BUFSIZE, 0);
        if (n < 0) {
            perror("Error in timesync recv");
            return;
        } else if (n != 8) {
            printf("Ignoring bogus timesync packet\n");
            continue;
        }

        htime_ns = *(uint64_t *)&buf[0];
        clock_gettime(CLOCK_REALTIME, &gtime);
        gtime_ns = gtime.tv_sec * NANOS_IN_SECOND;
        gtime_ns += gtime.tv_nsec;

        if (llabs(htime_ns - gtime_ns) > DELTA_SYNC) {
            htime.tv_sec = htime_ns / NANOS_IN_SECOND;
            htime.tv_nsec = htime_ns % NANOS_IN_SECOND;
            clock_settime(CLOCK_REALTIME, &htime);
        }
    }
}

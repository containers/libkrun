#ifndef TIMESYNC_H
#define TIMESYNC_H

#include <linux/vm_sockets.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>

#define TSYNC_PORT 123
#define BUFSIZE 8
#define NANOS_IN_SECOND 1000000000
/* Set clock if delta is bigger than 100ms */
#define DELTA_SYNC 100000000

void clock_worker();

#endif

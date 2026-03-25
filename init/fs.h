#ifndef FS_H
#define FS_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#define KRUN_REMOVE_ROOT_DIR_IOCTL 0x7603

void setup_root_block_device(void);
int is_virtiofs(const char *path);
int mount_filesystems();
int try_mount(const char *source, const char *target, const char *fstype,
              unsigned long mountflags, const void *data);

#endif

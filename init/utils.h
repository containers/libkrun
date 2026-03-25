#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <limits.h>

#include <net/if.h>
#include <linux/vm_sockets.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/resource.h>

#define KRUN_REMOVE_ROOT_DIR_IOCTL 0x7603
#define KRUN_EXIT_CODE_IOCTL 0x7602

#define MAX_PASS_SIZE 512

#define KRUN_MAGIC "KRUN"
#define KRUN_FOOTER_LEN 12

int mount_filesystems();
int try_mount(const char *source, const char *target, const char *fstype,
              unsigned long mountflags, const void *data);
void set_exit_code(int code);
int setup_redirects(void);
void set_rlimits(const char *rlimits);
int is_virtiofs(const char *path);
void setup_root_block_device(void);
void setup_socket(void);
void exec_init(char ***config_argv, char ***exec_argv);
void handle_env_variables(char *config_workdir);
void parent_proc_wait(int child, int *status);
void exec_child(char **exec_argv, int *saved_errno);

#endif

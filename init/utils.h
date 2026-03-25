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
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/resource.h>

#define KRUN_EXIT_CODE_IOCTL 0x7602

#define MAX_PASS_SIZE 512

#define KRUN_MAGIC "KRUN"
#define KRUN_FOOTER_LEN 12

void set_exit_code(int code);
int setup_redirects(void);
void set_rlimits(const char *rlimits);
void setup_socket(void);
void exec_init(char ***config_argv, char ***exec_argv);
void handle_env_variables(char *config_workdir);

#endif

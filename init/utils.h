#ifndef UTILS_H
#define UTILS_H

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/socket.h>
#include <linux/vm_sockets.h>
#include <net/if.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

#define KRUN_EXIT_CODE_IOCTL 0x7602
#define MAX_PASS_SIZE 512
#define KRUN_MAGIC "KRUN"
#define KRUN_FOOTER_LEN 12

void setup_socket(void);
void exec_init(char ***config_argv, char ***exec_argv);
void handle_env_variables(char *config_workdir);

#endif

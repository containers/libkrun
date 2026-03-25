#include <net/if.h>
#include <linux/vm_sockets.h>

#include "utils.h"
#include "parser.h"
#include "fs.h"

#ifdef __TIMESYNC__
#include "timesync.h"
#endif

int main(int argc, char **argv)
{
    char *config_workdir;
    char **config_argv, **exec_argv;

    if (mount_filesystems() < 0) {
        printf("Couldn't mount filesystems, bailing out\n");
        exit(-2);
    }

    setup_root_block_device();

    setsid();
    ioctl(0, TIOCSCTTY, 1);

    setup_socket();

    config_argv = NULL;
    config_workdir = NULL;

    config_parse_file(&config_argv, &config_workdir);

    handle_env_variables(config_workdir);

#ifdef __TIMESYNC__
    if (fork() == 0) {
        clock_worker();
        _exit(1);
    }
#endif

    exec_argv = argv;
    exec_init(&config_argv, &exec_argv);

    return 0;
}

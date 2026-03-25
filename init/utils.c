#include "utils.h"

char DEFAULT_KRUN_INIT[] = "/bin/sh";

static int reopen_fd(int fd, char *path, int flags);

int mount_filesystems()
{
    char *const DIRS_LEVEL1[] = {"/dev", "/proc", "/sys"};
    char *const DIRS_LEVEL2[] = {"/dev/pts", "/dev/shm"};
    int i;

    for (i = 0; i < 3; ++i) {
        if (mkdir(DIRS_LEVEL1[i], 0755) < 0 && errno != EEXIST) {
            printf("Error creating directory (%s)\n", DIRS_LEVEL1[i]);
            return -1;
        }
    }

    if (mount("devtmpfs", "/dev", "devtmpfs", MS_RELATIME, NULL) < 0 &&
        errno != EBUSY) {
        perror("mount(/dev)");
        return -1;
    }

    if (mount("proc", "/proc", "proc",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
        perror("mount(/proc)");
        return -1;
    }

    if (mount("sysfs", "/sys", "sysfs",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
        perror("mount(/sys)");
        return -1;
    }

    if (mount("cgroup2", "/sys/fs/cgroup", "cgroup2",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
        perror("mount(/sys/fs/cgroup)");
        return -1;
    }

    for (i = 0; i < 2; ++i) {
        if (mkdir(DIRS_LEVEL2[i], 0755) < 0 && errno != EEXIST) {
            printf("Error creating directory (%s)\n", DIRS_LEVEL2[i]);
            return -1;
        }
    }

    if (mount("devpts", "/dev/pts", "devpts",
              MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
        perror("mount(/dev/pts)");
        return -1;
    }

    if (mount("tmpfs", "/dev/shm", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_RELATIME,
              NULL) < 0) {
        perror("mount(/dev/shm)");
        return -1;
    }

    /* May fail if already exists and that's fine. */
    symlink("/proc/self/fd", "/dev/fd");

    return 0;
}

int try_mount(const char *source, const char *target, const char *fstype,
              unsigned long mountflags, const void *data)
{
    FILE *f;
    char line[129];
    int mount_status = -1;

    if (fstype) {
        return mount(source, target, fstype, mountflags, data);
    }

    f = fopen("/proc/filesystems", "r");
    if (f == NULL) {
        perror("fopen(/proc/filesystems)");
        return -1;
    }
    while (fgets(line, sizeof(line), f)) {
        char fstype[sizeof(line)];
        if (!strncmp(line, "nodev", 5)) {
            continue;
        }
        if (sscanf(line, "%128s\n", fstype) != 1) {
            continue;
        }

        mount_status = mount(source, target, fstype, mountflags, data);
        if (mount_status == 0) {
            break;
        }
    }
    fclose(f);

    return mount_status;
}

void set_exit_code(int code)
{
    int fd;
    int ret;
    int virtiofs_check;

    // Only use the ioctl if virtiofs is used for root filesystem
    virtiofs_check = is_virtiofs("/");
    if (virtiofs_check < 0) {
        printf("Warning: Could not determine filesystem type for root\n");
    }

    if (virtiofs_check == 0) {
        // Root filesystem is not virtiofs, skip the ioctl
        return;
    }

    fd = open("/", O_RDONLY);
    if (fd < 0) {
        perror("Couldn't open root filesystem to report exit code");
        return;
    }

    ret = ioctl(fd, KRUN_EXIT_CODE_IOCTL, code);
    if (ret < 0) {
        perror("Error using the ioctl to set the exit code");
    }

    close(fd);
}

int setup_redirects()
{
    DIR *ports_dir = opendir("/sys/class/virtio-ports");
    if (ports_dir == NULL) {
        printf("Unable to open ports directory!\n");
        return -4;
    }

    char path[2048];
    char name_buf[1024];

    struct dirent *entry = NULL;
    while ((entry = readdir(ports_dir))) {
        char *port_identifier = entry->d_name;
        int result_len =
            snprintf(path, sizeof(path), "/sys/class/virtio-ports/%s/name",
                     port_identifier);

        // result was truncated
        if (result_len > sizeof(name_buf) - 1) {
            printf("Path buffer too small");
            return -1;
        }

        FILE *port_name_file = fopen(path, "r");
        if (port_name_file == NULL) {
            continue;
        }

        char *port_name = fgets(name_buf, sizeof(name_buf), port_name_file);
        fclose(port_name_file);

        if (port_name != NULL && strcmp(port_name, "krun-stdin\n") == 0) {
            // if previous snprintf didn't fail, this one cannot fail either
            snprintf(path, sizeof(path), "/dev/%s", port_identifier);
            reopen_fd(STDIN_FILENO, path, O_RDONLY);
        } else if (port_name != NULL &&
                   strcmp(port_name, "krun-stdout\n") == 0) {
            snprintf(path, sizeof(path), "/dev/%s", port_identifier);
            reopen_fd(STDOUT_FILENO, path, O_WRONLY);
        } else if (port_name != NULL &&
                   strcmp(port_name, "krun-stderr\n") == 0) {
            snprintf(path, sizeof(path), "/dev/%s", port_identifier);
            reopen_fd(STDERR_FILENO, path, O_WRONLY);
        }
    }

    closedir(ports_dir);
    return 0;
}

static int reopen_fd(int fd, char *path, int flags)
{
    int newfd = open(path, flags);
    if (newfd < 0) {
        printf("Failed to open '%s': %s\n", path, strerror(errno));
        return -1;
    }

    close(fd);
    if (dup2(newfd, fd) < 0) {
        perror("dup2");
        close(newfd);
        return -1;
    }
    close(newfd);
    return 0;
}

void set_rlimits(const char *rlimits)
{
    unsigned long long int lim_id, lim_cur, lim_max;
    struct rlimit rlim;
    char *item = (char *)rlimits;

    while (1) {
        lim_id = lim_cur = lim_max = ULLONG_MAX;

        lim_id = strtoull(item, &item, 10);
        if (lim_id == ULLONG_MAX) {
            printf("Invalid rlimit ID\n");
            break;
        }

        item++;
        lim_cur = strtoull(item, &item, 10);
        item++;
        lim_max = strtoull(item, &item, 10);

        rlim.rlim_cur = lim_cur;
        rlim.rlim_max = lim_max;
        if (setrlimit(lim_id, &rlim) != 0) {
            printf("Error setting rlimit for ID=%lld\n", lim_id);
        }

        if (*item != '\0') {
            item++;
        } else {
            break;
        }
    }
}



int is_virtiofs(const char *path)
{
    struct statfs fs;

    if (statfs(path, &fs) != 0) {
        perror("statfs");
        return -1;
    }

    // virtiofs magic number: 0x65735546
    return (fs.f_type == 0x65735546) ? 1 : 0;
}

#ifdef __TIMESYNC__

#define TSYNC_PORT 123
#define BUFSIZE 8
#define NANOS_IN_SECOND 1000000000
/* Set clock if delta is bigger than 100ms */
#define DELTA_SYNC 100000000

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
#endif

void setup_root_block_device(void)
{
    int fd;
    char *krun_root;
    char *krun_root_fstype;
    char *krun_root_options;

    krun_root = getenv("KRUN_BLOCK_ROOT_DEVICE");
    if (krun_root) {
        if (mkdir("/newroot", 0755) < 0 && errno != EEXIST) {
            perror("mkdir(/newroot)");
            exit(-1);
        }

        krun_root_fstype = getenv("KRUN_BLOCK_ROOT_FSTYPE");
        krun_root_options = getenv("KRUN_BLOCK_ROOT_OPTIONS");

        if (try_mount(krun_root, "/newroot", krun_root_fstype, 0,
                      krun_root_options) < 0) {
            perror("mount KRUN_BLOCK_ROOT_DEVICE");
            exit(-1);
        }

        chdir("/newroot");

        fd = open("/", O_RDONLY);
        if (fd < 0) {
            perror("Couldn't open temporary root directory for removing");
            exit(-1);
        }
        if (ioctl(fd, KRUN_REMOVE_ROOT_DIR_IOCTL) < 0) {
            perror("Error removing temporary root directory");
        }
        close(fd);

        if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
            perror("remount root");
            exit(-1);
        }
        chroot(".");

        // we must mount filesystems again after chrooting
        if (mount_filesystems() < 0) {
            printf("Couldn't mount filesystems, bailing out\n");
            exit(-2);
        }
    }

    if (mount(NULL, "/", NULL, MS_REC | MS_SHARED, NULL) < 0) {
        perror("Couldn't set shared propagation on the root mount");
        exit(-1);
    }
}

void exec_child(char **exec_argv, int *saved_errno)
{
    if (setup_redirects() < 0) {
        exit(125);
    }
    if (execvp(exec_argv[0], exec_argv) < 0) {
        *saved_errno = errno;
        printf("Couldn't execute '%s' inside the vm: %s\n", exec_argv[0],
                strerror(errno));
        // Use the same exit code as chroot and podman do.
        if (*saved_errno == ENOENT) {
            exit(127);
        } else {
            exit(126);
        }
    }
}

void parent_proc_wait(int child, int *status)
{
    // Wait until the workload's entrypoint has exited, ignoring any other
    // children.
    while (waitpid(-1, status, 0) != child) {
        // Not the first child, ignore it.
    };

    // The workload's entrypoint has exited, record its exit code and exit
    // ourselves.
    if (WIFEXITED(*status)) {
        set_exit_code(WEXITSTATUS(*status));
    } else if (WIFSIGNALED(*status)) {
        set_exit_code(WTERMSIG(*status) + 128);
    }
}

void handle_env_variables(char *config_workdir)
{
    char *hostname;
    char localhost[] = "localhost\0";
    char *krun_home;
    char *krun_term;
    char *rlimits;
    char *env_workdir;
    
    krun_home = getenv("KRUN_HOME");
    if (krun_home) {
        setenv("HOME", krun_home, 1);
    }

    krun_term = getenv("KRUN_TERM");
    if (krun_term) {
        setenv("TERM", krun_term, 1);
    }

    hostname = getenv("HOSTNAME");
    if (hostname) {
        sethostname(hostname, strlen(hostname));
    } else {
        sethostname(&localhost[0], strlen(localhost));
    }

    rlimits = getenv("KRUN_RLIMITS");
    if (rlimits) {
        set_rlimits(rlimits);
    }

    env_workdir = getenv("KRUN_WORKDIR");
    if (env_workdir) {
        chdir(env_workdir);
    } else if (config_workdir) {
        chdir(config_workdir);
    }

}

void exec_init(char ***config_argv, char ***exec_argv)
{
    int saved_errno;
    int status;
    char *krun_init;
    char *env_init_pid1;
    bool init_pid1 = false;

    krun_init = getenv("KRUN_INIT");
    if (krun_init) {
        (*exec_argv)[0] = krun_init;
    } else if (config_argv) {
        *exec_argv = *config_argv;
    } else {
        (*exec_argv)[0] = &DEFAULT_KRUN_INIT[0];
    }

    env_init_pid1 = getenv("KRUN_INIT_PID1");
    if (env_init_pid1 && *env_init_pid1 == '1') {
        init_pid1 = true;
    }

    if (init_pid1) {
        goto exec_init;
    }

    // We need to fork ourselves, because pid 1 cannot doesn't receive SIGINT
    // signal
    int child = fork();
    if (child < 0) {
        perror("fork");
        set_exit_code(125);
        exit(125);
    }
    if (child == 0) { // child
    exec_init:
        exec_child(*exec_argv, &saved_errno);
    } else { // parent
        parent_proc_wait(child, &status);
    }
}

void setup_socket(void)
{
    struct ifreq ifr;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd >= 0) {
        memset(&ifr, 0, sizeof ifr);
        strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
        ifr.ifr_flags |= IFF_UP;
        ioctl(sockfd, SIOCSIFFLAGS, &ifr);
        close(sockfd);
    }

}

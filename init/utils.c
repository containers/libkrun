#include "utils.h"
#include "fs.h"

char DEFAULT_KRUN_INIT[] = "/bin/sh";

static int reopen_fd(int fd, char *path, int flags);
static void exec_child(char **exec_argv, int *saved_errno);
static void parent_proc_wait(int child, int *status);
static void set_exit_code(int code);
static int setup_redirects(void);
static void set_rlimits(const char *rlimits);

static void set_exit_code(int code)
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

static int setup_redirects()
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

static void set_rlimits(const char *rlimits)
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
    if (hostname && sethostname(hostname, strlen(hostname)) < 0) {
        perror("sethostname(getenv(HOSTNAME))");
        exit(-1);
    } else if (sethostname(&localhost[0], strlen(localhost)) < 0) {
        perror("sethostname(localhost)");
        exit(-1);
    }

    rlimits = getenv("KRUN_RLIMITS");
    if (rlimits) {
        set_rlimits(rlimits);
    }

    env_workdir = getenv("KRUN_WORKDIR");
    if (env_workdir && chdir(env_workdir) < 0) {
        perror("chdir(getenv(KRUN_WORKDIR))");
        exit(-1);
    } else if (config_workdir && chdir(config_workdir) < 0) {
        perror("chdir(config_workdir)");
        exit(-1);
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

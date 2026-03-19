#ifndef UTILS_H
#define UTILS_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/stat.h>

#include "jsmn.h"

#define CONFIG_FILE_PATH "/.krun_config.json"

#define KRUN_EXIT_CODE_IOCTL 0x7602

#define MAX_ARGS 32
#define MAX_PASS_SIZE 512
#define MAX_TOKENS 16384

#define KRUN_MAGIC "KRUN"
#define KRUN_FOOTER_LEN 12

int mount_filesystems();
int try_mount(const char *source, const char *target, const char *fstype,
              unsigned long mountflags, const void *data);
int config_parse_file(char ***argv, char **workdir);
void set_exit_code(int code);
int setup_redirects(void);
void set_rlimits(const char *rlimits);
char **concat_entrypoint_argv(char **entrypoint, char **config_argv);
int is_virtiofs(const char *path);

static int reopen_fd(int fd, char *path, int flags);
static void hexToDigit(unsigned int *val, const unsigned char *hex);
static void Utf32toUtf8(unsigned int codepoint, char *utf8Buf);
static void unescape_string(char *string, int len);
static void config_parse_env(char *data, jsmntok_t *token);
static char **config_parse_args(char *data, jsmntok_t *token);
static char *config_parse_string(char *data, jsmntok_t *token);
static int jsoneq(const char *, jsmntok_t *, const char *);

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

int config_parse_file(char ***argv, char **workdir)
{
    jsmn_parser parser;
    jsmntok_t *tokens;
    struct stat stat;
    char *data;
    char *config_file;
    char **config_argv;
    char **entrypoint;
    int parsed_env, parsed_workdir, parsed_args, parsed_entrypoint;
    int num_tokens;
    int ret = -1;
    int fd;
    int i;

    config_file = getenv("KRUN_CONFIG");
    if (!config_file) {
        config_file = CONFIG_FILE_PATH;
    }

    fd = open(config_file, O_RDONLY);
    if (fd < 0) {
        return ret;
    }

    if (fstat(fd, &stat) != 0) {
        perror("Couldn't stat config file");
        goto cleanup_fd;
    }

    data = malloc(stat.st_size);
    if (!data) {
        perror("Couldn't allocate memory");
        goto cleanup_fd;
    }

    if (read(fd, data, stat.st_size) < 0) {
        perror("Error reading config file");
        goto cleanup_data;
    }

    tokens = malloc(MAX_TOKENS * sizeof(jsmntok_t));
    if (!tokens) {
        perror("Couldn't allocate memory");
        goto cleanup_data;
    }

    jsmn_init(&parser);
    num_tokens = jsmn_parse(&parser, data, strlen(data), tokens, MAX_TOKENS);
    if (num_tokens < 0) {
        printf("Error parsing config file\n");
        goto cleanup_tokens;
    }

    if (num_tokens < 1 || tokens[0].type != JSMN_OBJECT) {
        printf("Couldn't find object in config file\n");
        goto cleanup_tokens;
    }

    config_argv = NULL;
    entrypoint = NULL;
    parsed_env = parsed_workdir = parsed_args = parsed_entrypoint = 0;

    for (i = 1; i < num_tokens && (!parsed_env || !parsed_args ||
                                   !parsed_workdir || !parsed_entrypoint);
         i++) {
        if (!parsed_env && jsoneq(data, &tokens[i], "Env") == 0 &&
            (i + 1) < num_tokens && tokens[i + 1].type == JSMN_ARRAY) {
            config_parse_env(data, &tokens[i + 1]);
            parsed_env = 1;
        }

        if (!parsed_args && jsoneq(data, &tokens[i], "args") == 0 &&
            (i + 1) < num_tokens) {
            config_argv = config_parse_args(data, &tokens[i + 1]);
            parsed_args = 1;
        }

        if (!parsed_args && jsoneq(data, &tokens[i], "Cmd") == 0 &&
            (i + 1) < num_tokens) {
            config_argv = config_parse_args(data, &tokens[i + 1]);
            parsed_args = 1;
        }

        if (!parsed_workdir && jsoneq(data, &tokens[i], "WorkingDir") == 0 &&
            (i + 1) < num_tokens) {
            *workdir = config_parse_string(data, &tokens[i + 1]);
            parsed_workdir = 1;
        }

        if (!parsed_workdir && jsoneq(data, &tokens[i], "Cwd") == 0 &&
            (i + 1) < num_tokens) {
            *workdir = config_parse_string(data, &tokens[i + 1]);
            parsed_workdir = 1;
        }

        if (!parsed_entrypoint && jsoneq(data, &tokens[i], "Entrypoint") == 0 &&
            (i + 1) < num_tokens) {
            entrypoint = config_parse_args(data, &tokens[i + 1]);
            parsed_entrypoint = 1;
        }
    }

    if (config_argv && entrypoint) {
        *argv = concat_entrypoint_argv(entrypoint, config_argv);
    } else {
        *argv = config_argv;
    }

    ret = 0;

cleanup_tokens:
    free(tokens);
cleanup_data:
    free(data);
cleanup_fd:
    close(fd);

    return ret;
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

/*
 * hexToDigit, Utf32toUtf8 and parts of unescape_string are taken from libyajl:
 *
 * Copyright (c) 2007-2014, Lloyd Hilaiel <me@lloyd.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
static void hexToDigit(unsigned int *val, const unsigned char *hex)
{
    unsigned int i;
    for (i = 0; i < 4; i++) {
        unsigned char c = hex[i];
        if (c >= 'A')
            c = (c & ~0x20) - 7;
        c -= '0';
        *val = (*val << 4) | c;
    }
}

static void Utf32toUtf8(unsigned int codepoint, char *utf8Buf)
{
    if (codepoint < 0x80) {
        utf8Buf[0] = (char)codepoint;
        utf8Buf[1] = 0;
    } else if (codepoint < 0x0800) {
        utf8Buf[0] = (char)((codepoint >> 6) | 0xC0);
        utf8Buf[1] = (char)((codepoint & 0x3F) | 0x80);
        utf8Buf[2] = 0;
    } else if (codepoint < 0x10000) {
        utf8Buf[0] = (char)((codepoint >> 12) | 0xE0);
        utf8Buf[1] = (char)(((codepoint >> 6) & 0x3F) | 0x80);
        utf8Buf[2] = (char)((codepoint & 0x3F) | 0x80);
        utf8Buf[3] = 0;
    } else if (codepoint < 0x200000) {
        utf8Buf[0] = (char)((codepoint >> 18) | 0xF0);
        utf8Buf[1] = (char)(((codepoint >> 12) & 0x3F) | 0x80);
        utf8Buf[2] = (char)(((codepoint >> 6) & 0x3F) | 0x80);
        utf8Buf[3] = (char)((codepoint & 0x3F) | 0x80);
        utf8Buf[4] = 0;
    } else {
        utf8Buf[0] = '?';
        utf8Buf[1] = 0;
    }
}

/* Do not worry about invalid JSON, it was already parsed by jsmn.  */
static void unescape_string(char *string, int len)
{
    unsigned char *val = (unsigned char *)string;
    unsigned char *end;
    int i = 0;

    end = val + len;
    while (val < end) {
        if (*val != '\\') {
            string[i++] = *val++;
            continue;
        }
        switch (*++val) {
        case 'n':
            string[i++] = '\n';
            break;
        case 't':
            string[i++] = '\t';
            break;
        case 'r':
            string[i++] = '\r';
            break;
        case 'b':
            string[i++] = '\b';
            break;
        case 'f':
            string[i++] = '\f';
            break;
        case '\\':
            string[i++] = '\\';
            break;
        case '\"':
            string[i++] = '\"';
            break;
        case '/':
            string[i++] = '/';
            break;
        case 'u': {
            const char *unescaped = "?";
            char utf8Buf[5];
            unsigned int codepoint = 0;
            hexToDigit(&codepoint, val++);
            val += 3;
            /* check if this is a surrogate */
            if ((codepoint & 0xFC00) == 0xD800) {
                val++;
                if (val[0] == '\\' && val[1] == 'u') {
                    unsigned int surrogate = 0;
                    hexToDigit(&surrogate, val + 2);
                    codepoint = (((codepoint & 0x3F) << 10) |
                                 ((((codepoint >> 6) & 0xF) + 1) << 16) |
                                 (surrogate & 0x3FF));
                    val += 5;
                } else {
                    unescaped = "?";
                    break;
                }
            }

            Utf32toUtf8(codepoint, utf8Buf);
            unescaped = utf8Buf;

            if (codepoint == 0) {
                memcpy(&string[i++], unescaped, 1);
                continue;
            }
            memcpy(&string[i], unescaped, (unsigned int)strlen(unescaped));
            break;
        }
        }
    }
    string[i] = '\0';
}

static void config_parse_env(char *data, jsmntok_t *token)
{
    jsmntok_t *tenv;
    char *env, *env_val;
    int len;
    int i;

    for (i = 0; i < token->size; i++) {
        tenv = &token[i + 1];

        env = data + tenv->start;
        len = tenv->end - tenv->start;

        unescape_string(env, len);

        env_val = strstr(env, "=");
        if (!env_val) {
            continue;
        }

        env[len] = '\0';
        *env_val = '\0';
        env_val++;

        if ((strcmp(env, "HOME") == 0) || (strcmp(env, "TERM") == 0)) {
            setenv(env, env_val, 1);
        } else {
            setenv(env, env_val, 0);
        }
    }
}

static char **config_parse_args(char *data, jsmntok_t *token)
{
    jsmntok_t *targ;
    char *arg, *value;
    char **argv;
    int len;
    int i, j;

    argv = malloc(MAX_ARGS * sizeof(char *));
    j = 0;

    for (i = 0; i < token->size; i++) {
        targ = &token[i + 1];

        value = data + targ->start;
        len = targ->end - targ->start;

        arg = malloc(len + 1);
        memcpy(arg, value, len);
        arg[len] = '\0';

        unescape_string(arg, len);

        argv[j] = arg;
        j++;
    }

    if (j == 0) {
        free(argv);
        argv = NULL;
    } else {
        argv[j] = NULL;
    }

    return argv;
}

static char *config_parse_string(char *data, jsmntok_t *token)
{
    char *string;
    char *val;
    int len;

    val = data + token->start;
    len = token->end - token->start;
    if (!len) {
        return NULL;
    }

    string = malloc(len + 1);

    if (!string) {
        return NULL;
    }
    memcpy(string, val, len);
    string[len] = '\0';

    unescape_string(string, len);

    return string;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncasecmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

char **concat_entrypoint_argv(char **entrypoint, char **config_argv)
{
    char **argv;
    int i, j;

    argv = malloc(MAX_ARGS * sizeof(char *));

    for (i = 0; i < MAX_ARGS && entrypoint[i]; i++) {
        argv[i] = entrypoint[i];
    }

    for (j = 0; j < MAX_ARGS && config_argv[j]; i++, j++) {
        argv[i] = config_argv[j];
    }

    argv[i] = NULL;

    return argv;
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

#endif

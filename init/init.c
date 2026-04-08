#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/vm_sockets.h>

#include "fs.h"
#include "jsmn.h"

#define KRUN_EXIT_CODE_IOCTL 0x7602

#define KRUN_MAGIC "KRUN"
#define KRUN_FOOTER_LEN 12
#define CONFIG_FILE_PATH "/.krun_config.json"
#define MAX_PASS_SIZE 512
#define MAX_TOKENS 16384

static int jsoneq(const char *, jsmntok_t *, const char *);

char DEFAULT_KRUN_INIT[] = "/bin/sh";

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
    int i;
    const int n_args = token->size;

    argv = malloc((n_args + 1) * sizeof(char *));
    if (!argv) {
        perror("malloc(config_parse_args)");
        return NULL;
    }

    for (i = 0; i < n_args; i++) {
        targ = &token[i + 1];

        value = data + targ->start;
        len = targ->end - targ->start;

        arg = malloc(len + 1);
        if (!arg) {
            perror("malloc(config_parse_args arg)");
            while (--i >= 0)
                free(argv[i]);
            free(argv);
            return NULL;
        }
        memcpy(arg, value, len);
        arg[len] = '\0';

        unescape_string(arg, len);

        argv[i] = arg;
    }

    if (i == 0) {
        free(argv);
        argv = NULL;
    } else {
        argv[i] = NULL;
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
    int n_args = 0;

    for (i = 0; entrypoint[i]; i++)
        n_args++;
    for (j = 0; config_argv[j]; j++)
        n_args++;

    argv = malloc((n_args + 1) * sizeof(char *));
    if (!argv) {
        perror("malloc(concat_entrypoint_argv)");
        return NULL;
    }

    for (i = 0; entrypoint[i]; i++) {
        argv[i] = entrypoint[i];
    }

    for (j = 0; config_argv[j]; i++, j++) {
        argv[i] = config_argv[j];
    }

    argv[i] = NULL;

    return argv;
}

static int config_parse_file(char ***argv, char **workdir)
{
    jsmn_parser parser;
    jsmntok_t *tokens;
    struct stat stat;
    char *data;
    off_t data_len;
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

    data_len = stat.st_size;
    data = malloc(data_len);
    if (!data) {
        perror("Couldn't allocate memory");
        goto cleanup_fd;
    }

    if (read(fd, data, data_len) < 0) {
        perror("Error reading config file");
        goto cleanup_data;
    }

    tokens = malloc(MAX_TOKENS * sizeof(jsmntok_t));
    if (!tokens) {
        perror("Couldn't allocate memory");
        goto cleanup_data;
    }

    jsmn_init(&parser);
    num_tokens = jsmn_parse(&parser, data, data_len, tokens, MAX_TOKENS);
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

#ifdef __TIMESYNC__
#include "timesync.h"
#endif

int reopen_fd(int fd, char *path, int flags)
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

int main(int argc, char **argv)
{
    struct ifreq ifr;
    int sockfd;
    int status;
    int saved_errno;
    bool init_pid1 = false;
    char localhost[] = "localhost\0";
    char *hostname;
    char *krun_home;
    char *krun_term;
    char *krun_init;
    char *env_init_pid1;
    char *config_workdir, *env_workdir;
    char *rlimits;
    char **config_argv, **exec_argv;

    if (mount_filesystems() < 0) {
        printf("Couldn't mount filesystems, bailing out\n");
        exit(-2);
    }

    setup_root_block_device();

    setsid();
    ioctl(0, TIOCSCTTY, 1);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd >= 0) {
        memset(&ifr, 0, sizeof ifr);
        strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
        ifr.ifr_flags |= IFF_UP;
        ioctl(sockfd, SIOCSIFFLAGS, &ifr);
        close(sockfd);
    }

    config_argv = NULL;
    config_workdir = NULL;

    config_parse_file(&config_argv, &config_workdir);

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

    exec_argv = argv;
    krun_init = getenv("KRUN_INIT");
    if (krun_init) {
        exec_argv[0] = krun_init;
    } else if (config_argv) {
        exec_argv = config_argv;
    } else {
        exec_argv[0] = &DEFAULT_KRUN_INIT[0];
    }

    env_init_pid1 = getenv("KRUN_INIT_PID1");
    if (env_init_pid1 && *env_init_pid1 == '1') {
        init_pid1 = true;
    }

#ifdef __TIMESYNC__
    if (fork() == 0) {
        clock_worker();
        _exit(1);
    }
#endif

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
        if (setup_redirects() < 0) {
            exit(125);
        }
        if (execvp(exec_argv[0], exec_argv) < 0) {
            saved_errno = errno;
            printf("Couldn't execute '%s' inside the vm: %s\n", exec_argv[0],
                   strerror(errno));
            // Use the same exit code as chroot and podman do.
            if (saved_errno == ENOENT) {
                exit(127);
            } else {
                exit(126);
            }
        }
    } else { // parent
        // Wait until the workload's entrypoint has exited, ignoring any other
        // children.
        while (waitpid(-1, &status, 0) != child) {
            // Not the first child, ignore it.
        };

        // The workload's entrypoint has exited, record its exit code and exit
        // ourselves.
        if (WIFEXITED(status)) {
            set_exit_code(WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            set_exit_code(WTERMSIG(status) + 128);
        }
    }

    return 0;
}

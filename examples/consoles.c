#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <libkrun.h>

#define NUM_RESERVED_PORTS 64

static int cmd_output(char *output, size_t output_size, const char *prog, ...)
{
    va_list args;
    const char *argv[32];
    int argc = 0;
    int pipe_fds[2] = { -1, -1 };

    argv[argc++] = prog;
    va_start(args, prog);
    while (argc < 31) {
        const char *arg = va_arg(args, const char *);
        argv[argc++] = arg;
        if (arg == NULL) break;
    }
    va_end(args);
    argv[argc] = NULL;

    if (output && output_size > 0) {
        if (pipe(pipe_fds) < 0) return -1;
    }

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (pipe_fds[0] >= 0) {
            close(pipe_fds[0]);
            dup2(pipe_fds[1], STDOUT_FILENO);
            close(pipe_fds[1]);
        }
        execvp(prog, (char *const *)argv);
        abort();
    }

    if (pipe_fds[0] >= 0) {
        close(pipe_fds[1]);
        ssize_t n = read(pipe_fds[0], output, output_size - 1);
        close(pipe_fds[0]);
        if (n < 0) n = 0;
        output[n] = '\0';
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

#define cmd(...) ({ char _d[1]; cmd_output(_d, 0, __VA_ARGS__); })

static int create_tmux_tty(const char *session_name)
{
    char tty_path[256];
    char wait_cmd[128];

    snprintf(wait_cmd, sizeof(wait_cmd), "waitpid %d", (int)getpid());
    if (cmd("tmux", "new-session", "-d", "-s", session_name, "sh", "-c", wait_cmd, NULL) != 0)
        return -1;

    char hook_cmd[128];
    snprintf(hook_cmd, sizeof(hook_cmd), "run-shell 'kill -WINCH %d'", (int)getpid());
    cmd("tmux", "set-hook", "-g", "client-resized", hook_cmd, NULL);

    if (cmd_output(tty_path, sizeof(tty_path), "tmux", "display-message", "-p", "-t", session_name, "#{pane_tty}", NULL) != 0)
        return -1;
    tty_path[strcspn(tty_path, "\n")] = '\0';

    int fd = open(tty_path, O_RDWR);
    if (fd < 0) return -1;
    return fd;
}

static int mkfifo_if_needed(const char *path)
{
    if (mkfifo(path, 0666) < 0) {
        if (errno != EEXIST) return -1;
    }
    return 0;
}

static int create_fifo_inout(const char *fifo_in, const char *fifo_out, int *input_fd, int *output_fd)
{
    if (mkfifo_if_needed(fifo_in) < 0) return -1;
    if (mkfifo_if_needed(fifo_out) < 0) return -1;

    *input_fd = open(fifo_in, O_RDWR | O_NONBLOCK);
    if (*input_fd < 0) return -1;

    *output_fd = open(fifo_out, O_RDWR | O_NONBLOCK);
    if (*output_fd < 0) {
        close(*input_fd);
        return -1;
    }

    return 0;
}

struct console_state {
    uint32_t ctx_id;
    uint32_t console_id;
    int ready_fd;
};

static void *dynamic_console_thread(void *arg)
{
    struct console_state *state = arg;
    int ready_fd = state->ready_fd;

    struct pollfd pfd = { .fd = ready_fd, .events = POLLIN };
    fprintf(stderr, "Waiting for console device...\n");
    if (poll(&pfd, 1, -1) < 0) {
        perror("poll");
        return NULL;
    }

    uint64_t val;
    if (read(ready_fd, &val, sizeof(val)) != sizeof(val)) {
        perror("read eventfd");
        return NULL;
    }

    fprintf(stderr, "\n");
    fprintf(stderr, "=== VM Started ===\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "*** To interact with the VM (hvc0), run in another terminal: ***\n");
    fprintf(stderr, "    tmux attach -t krun-console-1\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Commands: 'c' = add console\n");
    fprintf(stderr, "          'p' = add pipe\n");
    fprintf(stderr, "\n");

    int console_count = 1;  /* console-1 already exists (hvc0) */
    int pipe_count = 0;
    char line[16];
    while (1) {
        fprintf(stderr, "> ");
        if (fgets(line, sizeof(line), stdin) == NULL) break;

        if (line[0] == 'c' || line[0] == 'C') {
            console_count++;
            char sess[64], port[64];
            snprintf(sess, sizeof(sess), "krun-console-%d", console_count);
            snprintf(port, sizeof(port), "console-%d", console_count);

            int fd = create_tmux_tty(sess);
            if (fd < 0) { fprintf(stderr, "tmux: failed to create session '%s'\n", sess); continue; }

            int err = krun_add_console_port_tty(state->ctx_id, state->console_id, port, fd);
            if (err) { fprintf(stderr, "add port: %s\n", strerror(-err)); close(fd); continue; }

            fprintf(stderr, "Created console '%s' (port %d, /dev/hvc%d):\n", port, console_count + pipe_count - 1, console_count - 1);
            fprintf(stderr, "  On host:  tmux attach -t %s\n", sess);
            fprintf(stderr, "  In guest: setsid /sbin/agetty -a $(whoami) -L hvc%d xterm-256color\n", console_count - 1);
            if (console_count + pipe_count > NUM_RESERVED_PORTS) {
                fprintf(stderr, "Reached max reserved ports (%d)\n", NUM_RESERVED_PORTS);
                break;
            }
        }

        if (line[0] == 'p' || line[0] == 'P') {
            pipe_count++;
            char port[64], fifo_in[128], fifo_out[128];
            snprintf(port, sizeof(port), "pipe-%d", pipe_count);
            snprintf(fifo_in, sizeof(fifo_in), "/tmp/krun_pipe%d_in", pipe_count);
            snprintf(fifo_out, sizeof(fifo_out), "/tmp/krun_pipe%d_out", pipe_count);

            int in_fd, out_fd;
            if (create_fifo_inout(fifo_in, fifo_out, &in_fd, &out_fd) < 0) {
                perror("create_fifo_inout"); continue;
            }

            int err = krun_add_console_port_inout(state->ctx_id, state->console_id, port, in_fd, out_fd);
            if (err) {
                fprintf(stderr, "add port: %s\n", strerror(-err));
                close(in_fd);
                close(out_fd);
                continue;
            }

            fprintf(stderr, "Created pipe '%s' (port %d):\n", port, console_count + pipe_count - 1);
            fprintf(stderr, "  In guest: DEV=/dev/$(grep -l %s /sys/class/virtio-ports/*/name | cut -d/ -f5)\n", port);
            fprintf(stderr, "            cat $DEV  OR  echo data > $DEV\n");
            fprintf(stderr, "  On host:  echo 'data' > %s   # send to guest\n", fifo_in);
            fprintf(stderr, "            cat %s             # receive from guest\n", fifo_out);
            if (console_count + pipe_count > NUM_RESERVED_PORTS) {
                fprintf(stderr, "Reached max reserved ports (%d)\n", NUM_RESERVED_PORTS);
                break;
            }
        }
    }

    return NULL;
}

int main(int argc, char *const argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s ROOT_DIR COMMAND [ARGS...]\n", argv[0]);
        return 1;
    }

    const char *root_dir = argv[1];
    const char *command = argv[2];
    const char *const *command_args = (argc > 3) ? (const char *const *)&argv[3] : NULL;
    const char *const envp[] = { 0 };

    krun_set_log_level(KRUN_LOG_LEVEL_DEBUG);

    int err;
    int ctx_id = krun_create_ctx();
    if (ctx_id < 0) { errno = -ctx_id; perror("krun_create_ctx"); return 1; }

    if ((err = krun_disable_implicit_console(ctx_id))) {
        errno = -err; perror("krun_disable_implicit_console"); return 1;
    }

    int console_id = krun_add_virtio_console_multiport(ctx_id);
    if (console_id < 0) {
        errno = -console_id; perror("krun_add_virtio_console_multiport"); return 1;
    }

    /* Create 1 initial console BEFORE VM starts - this will run the command */
    {
        int fd = create_tmux_tty("krun-console-1");
        if (fd < 0) { fprintf(stderr, "create_tmux_tty failed (session already exists?)\n"); return 1; }
        if ((err = krun_add_console_port_tty(ctx_id, console_id, "console-1", fd))) {
            errno = -err; perror("krun_add_console_port_tty"); return 1;
        }
    }

    /* Reserve ports for dynamic addition */
    if ((err = krun_console_reserve_ports(ctx_id, console_id, NUM_RESERVED_PORTS))) {
        errno = -err; perror("krun_console_reserve_ports"); return 1;
    }

    if ((err = krun_set_vm_config(ctx_id, 4, 4096))) {
        errno = -err; perror("krun_set_vm_config"); return 1;
    }
    if ((err = krun_set_root(ctx_id, root_dir))) {
        errno = -err; perror("krun_set_root"); return 1;
    }
    if ((err = krun_set_exec(ctx_id, command, command_args, envp))) {
        errno = -err; perror("krun_set_exec"); return 1;
    }

    fprintf(stderr, "\nStarting VM...\n");

    int ready_fd = krun_get_console_ready_fd(ctx_id, console_id);
    if (ready_fd < 0) {
        errno = -ready_fd; perror("krun_get_console_ready_fd"); return 1;
    }

    struct console_state state = {
        .ctx_id = ctx_id,
        .console_id = console_id,
        .ready_fd = ready_fd,
    };

    pthread_t dyn_thread;
    pthread_create(&dyn_thread, NULL, dynamic_console_thread, &state);
    pthread_detach(dyn_thread);

    /* Run VM in main thread - this blocks until VM exits, then calls _exit() */
    if ((err = krun_start_enter(ctx_id))) {
        errno = -err; perror("krun_start_enter"); return 1;
    }

    return 0;
}

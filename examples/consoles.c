#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <libkrun.h>

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

    // Hook up tmux to send us SIGWINCH signal on resize
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

    int in_fd = open(fifo_in, O_RDONLY | O_NONBLOCK);
    if (in_fd < 0) return -1;

    int out_fd = open(fifo_out, O_RDWR | O_NONBLOCK);
    if (out_fd < 0) { close(in_fd); return -1; }

    *input_fd = in_fd;
    *output_fd = out_fd;
    return 0;
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

    krun_set_log_level(KRUN_LOG_LEVEL_WARN);

    int err;
    int ctx_id = krun_create_ctx();
    if (ctx_id < 0) { errno = -ctx_id; perror("krun_create_ctx"); return 1; }

    if ((err = krun_disable_implicit_console(ctx_id))) {
        errno = -err;
        perror("krun_disable_implicit_console");
        return 1;
    }

    int console_id = krun_add_virtio_console_multiport(ctx_id);
    if (console_id < 0) {
        errno = -console_id;
        perror("krun_add_virtio_console_multiport");
        return 1;
    }

    /* Configure console ports - edit this section to add/remove ports */
    {
        
        // You could also use the controlling terminal of this process in the guest: 
        /* 
        if ((err = krun_add_console_port_tty(ctx_id, console_id, "host_tty", open("/dev/tty", O_RDWR)))) {
            errno = -err; 
            perror("port host_tty"); 
            return 1;
        }
        */

        int num_consoles = 3;
        for (int i = 0; i < num_consoles; i++) {
            char session_name[64];
            char port_name[64];
            snprintf(session_name, sizeof(session_name), "krun-console-%d", i + 1);
            snprintf(port_name, sizeof(port_name), "console-%d", i + 1);

            int tmux_fd = create_tmux_tty(session_name);
            if (tmux_fd < 0) {
                perror("create_tmux_tty");
                return 1;
            }
            if ((err = krun_add_console_port_tty(ctx_id, console_id, port_name, tmux_fd))) {
                errno = -err;
                perror("krun_add_console_port_tty");
                return 1;
            }
        }

        int in_fd, out_fd;
        if (create_fifo_inout("/tmp/consoles_example_in", "/tmp/consoles_example_out", &in_fd, &out_fd) < 0) {
            perror("create_fifo_inout");
            return 1;
        }
        if ((err = krun_add_console_port_inout(ctx_id, console_id, "fifo_inout", in_fd, out_fd))) {
            errno = -err;
            perror("krun_add_console_port_inout");
            return 1;
        }

        fprintf(stderr, "\n=== Console ports configured ===\n");
        for (int i = 0; i < num_consoles; i++) {
            fprintf(stderr, "  console-%d: tmux attach -t krun-console-%d\n", i + 1, i + 1);
        }
        fprintf(stderr, "  fifo_inout: /tmp/consoles_example_in (host->guest)\n");
        fprintf(stderr, "  fifo_inout: /tmp/consoles_example_out (guest->host)\n");
        fprintf(stderr, "================================\n\n");
    }

    if ((err = krun_set_vm_config(ctx_id, 4, 4096))) {
        errno = -err;
        perror("krun_set_vm_config");
        return 1;
    }

    if ((err = krun_set_root(ctx_id, root_dir))) {
        errno = -err;
        perror("krun_set_root");
        return 1;
    }

    if ((err = krun_set_exec(ctx_id, command, command_args, envp))) {
        errno = -err;
        perror("krun_set_exec");
        return 1;
    }

    if ((err = krun_start_enter(ctx_id))) {
        errno = -err;
        perror("krun_start_enter");
        return 1;
    }
    return 0;
}



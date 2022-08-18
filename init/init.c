#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "jsmn.h"

#define CMDLINE_SECRET_PATH "/sfs/secrets/coco/cmdline"
#define CONFIG_FILE_PATH "/.krun_config.json"
#define MAX_ARGS 32
#define MAX_PASS_SIZE 512
#define MAX_TOKENS 16384

char DEFAULT_KRUN_INIT[] = "/bin/sh";

static void set_rlimits(const char *rlimits)
{
	unsigned long long int lim_id, lim_cur, lim_max;
	struct rlimit rlim;
	char *item = (char *) rlimits;

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

#ifdef SEV
static char * get_luks_passphrase(int *pass_len)
{
	char *pass = NULL;
	int len;
	int fd;

	pass = getenv("KRUN_PASS");
	if (pass) {
		*pass_len = strnlen(pass, MAX_PASS_SIZE);
		return pass;
	}

	if (mkdir("/sfs", 0755) < 0 && errno != EEXIST) {
		perror("mkdir(/sfs)");
		return NULL;
	}

	if (mount("securityfs", "/sfs", "securityfs",
		  MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
		perror("mount(/sfs)");
		goto cleanup_dir;
	}

	fd = open(CMDLINE_SECRET_PATH, O_RDONLY);
	if (fd < 0) {
		goto cleanup_sfs;
	}

	pass = malloc(MAX_PASS_SIZE);
	if (!pass) {
		goto cleanup_fd;
	}

	if ((len = read(fd, pass, MAX_PASS_SIZE)) < 0) {
		free(pass);
		pass = NULL;
	} else {
		*pass_len = len;
		unlink(CMDLINE_SECRET_PATH);
	}

cleanup_fd:
	close(fd);
cleanup_sfs:
	umount("/sfs");
cleanup_dir:
	rmdir("/sfs");

	return pass;
}

static int chroot_luks()
{
	char *pass;
	int pass_len;
	int pid;
	int pipefd[2];
	int wstatus;

	pass = get_luks_passphrase(&pass_len);
	if (!pass) {
		printf("Couldn't find LUKS passphrase\n");
		return -1;
	}

	printf("Unlocking LUKS root filesystem\n");

	if (mount("proc", "/proc", "proc",
		  MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
		perror("mount(/proc)");
		return -1;
	}

	pipe(pipefd);

	pid = fork();
	if (pid == 0) {
		close(pipefd[1]);
		dup2(pipefd[0], 0);
		close(pipefd[0]);

		if (execl("/sbin/cryptsetup", "cryptsetup", "open", "/dev/vda", "luksroot", "-", NULL) < 0) {
			perror("execl");
			return -1;
		}
	} else {
		write(pipefd[1], pass, strnlen(pass, pass_len));
		close(pipefd[1]);
		waitpid(pid, &wstatus, 0);
	}

	memset(pass, 0, pass_len);

	printf("Mounting LUKS root filesystem\n");

	if (mount("/dev/mapper/luksroot", "/luksroot", "ext4", 0, NULL) < 0) {
		perror("mount(/luksroot)");
		return -1;
	}

	chdir("/luksroot");

	if (mount(".", "/", NULL, MS_MOVE, NULL)) {
		perror("remount root");
		return -1;
	}
	chroot(".");

	return 0;
}
#endif

static int create_dirs()
{
	char *const DIRS[] = {"/proc", "/sys", "/sys/fs", "/sys/fs/cgroup", "/dev/pts", "/dev/shm"};
	int i;

	if (access("/dev", F_OK) != 0) {
		if (mkdir("/dev", 0755) < 0 && errno != EEXIST) {
			printf("Error creating directory /dev\n");
			return -1;
		}
		if (mount("devtmpfs", "/dev", "devtmpfs",
			  MS_RELATIME, NULL) < 0) {
			perror("mount(/dev)");
			return -1;
		}
	}

	for (i = 0; i < 6; ++i) {
		if (mkdir(DIRS[i], 0755) < 0 && errno != EEXIST) {
			printf("Error creating directory (%s)\n", DIRS[i]);
			return -1;
		}
	}

	return 0;
}

static int mount_filesystems()
{
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

	if (mount("devpts", "/dev/pts", "devpts",
		  MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
		perror("mount(/dev/pts)");
		return -1;
	}

	if (mount("tmpfs", "/dev/shm", "tmpfs",
		  MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL) < 0) {
		perror("mount(/dev/shm)");
		return -1;
	}

	/* May fail if already exists and that's fine. */
	symlink("/proc/self/fd", "/dev/fd");

	return 0;
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

		env_val = strstr(env, "=");
		if (!env_val) {
			continue;
		}

		env[len] = '\0';
		*env_val = '\0';
		env_val++;

		setenv(env, env_val, 0);
	}
}

static char ** config_parse_args(char *data, jsmntok_t *token)
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

static char * config_parse_string(char *data, jsmntok_t *token)
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

	return string;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
	    strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

char ** concat_entrypoint_argv(char **entrypoint, char **config_argv)
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

static int config_parse_file(char ***argv, char **workdir)
{
	jsmn_parser parser;
	jsmntok_t *tokens;
	struct stat stat;
	char *data;
	char **config_argv;
	char **entrypoint;
	int parsed_env, parsed_workdir, parsed_args, parsed_entrypoint;
	int num_tokens;
	int ret = -1;
	int fd;
	int i;

	fd = open(CONFIG_FILE_PATH, O_RDONLY);
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
	num_tokens = jsmn_parse(&parser, data, strlen(data),
				tokens, MAX_TOKENS);
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

	for (i = 1; i < num_tokens && (!parsed_env || !parsed_args || !parsed_workdir); i++) {
		if (!parsed_env && jsoneq(data, &tokens[i], "Env") == 0) {
			config_parse_env(data, &tokens[i + 1]);
			parsed_env = 1;
		}

		if (!parsed_args && jsoneq(data, &tokens[i], "Cmd") == 0) {
			config_argv = config_parse_args(data, &tokens[i + 1]);
			parsed_args = 1;
		}

		if (!parsed_workdir && jsoneq(data, &tokens[i], "WorkingDir") == 0) {
			*workdir = config_parse_string(data, &tokens[i + 1]);
			parsed_workdir = 1;
		}

		if (!parsed_entrypoint && jsoneq(data, &tokens[i], "Entrypoint") == 0) {
			entrypoint = config_parse_args(data, &tokens[i + 1]);
			parsed_workdir = 1;
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

int main(int argc, char **argv)
{
	struct ifreq ifr;
	int sockfd;
	char localhost[] = "localhost\0";
	char *hostname;
	char *krun_init;
	char *config_workdir, *env_workdir;
	char *rlimits;
	char **config_argv, **exec_argv;

#ifdef SEV
	if (chroot_luks() < 0) {
		printf("Couldn't switch to LUKS volume, bailing out\n");
		exit(-1);
	}
#endif

	if (create_dirs() < 0) {
		printf("Couldn't create support directories, bailing out\n");
		exit(-2);
	}

	if (mount_filesystems() < 0) {
		printf("Couldn't mount filesystems, bailing out\n");
		exit(-3);
	}

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

	execvp(exec_argv[0], exec_argv);

	return 0;
}

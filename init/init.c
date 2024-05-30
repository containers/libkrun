#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <termios.h>

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
#include <linux/vm_sockets.h>

#include "jsmn.h"

#ifdef SEV
#include "tee/snp_attest.h"
#endif

#define KRUN_MAGIC "KRUN"
#define KRUN_FOOTER_LEN 12
#define CMDLINE_SECRET_PATH "/sfs/secrets/coco/cmdline"
#define CONFIG_FILE_PATH "/.krun_config.json"
#define MAX_ARGS 32
#define MAX_PASS_SIZE 512
#define MAX_TOKENS 16384

static int jsoneq(const char *, jsmntok_t *, const char *);

#ifdef SEV
static char *sev_get_luks_passphrase(int *);
static char *snp_get_luks_passphrase(char *, char *, char *, int *);
#endif

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
/*
 * The LUKS passphrase is obtained from a KBS attestation server, complete an
 * SNP attestation to get the passphrase.
 */
static char *
get_luks_passphrase(int *pass_len)
{
        int fd, ret, num_tokens, wid_found, url_found, tee_found, tee_data_found;
        uint64_t dev_size, tc_size;
        char wid[256], url[256], *tc_json, *tok_start, *tok_end;
        char footer[KRUN_FOOTER_LEN], tee[256], tee_data[256], *return_str;
        jsmn_parser parser;
        jsmntok_t *tokens;
        size_t tok_size;

        return_str = NULL;

        /*
         * If a user registered the TEE config data disk with
         * krun_set_data_disk(), it would appear as /dev/vdb in the guest.
         * Mount this device and read the config.
         */
        if (mkdir("/dev", 0755) < 0 && errno != EEXIST) {
                perror("mkdir(/dev)");
                goto finish;
        }

        if (mount("devtmpfs", "/dev", "devtmpfs", MS_RELATIME, NULL) < 0 &&
                        errno != EBUSY) {
                perror("mount(devtmpfs)");

                goto rmdir_dev;
        }

        fd = open("/dev/vda", O_RDONLY);
        if (fd < 0) {
            perror("open(/dev/vda)");

            goto umount_dev;
        }

        ret = ioctl(fd, BLKGETSIZE64, &dev_size);
        if (ret != 0) {
            perror("ioctl(BLKGETSIZE64)");

            goto close_dev;
        }

        if (lseek(fd, dev_size - KRUN_FOOTER_LEN, SEEK_SET) == -1) {
            perror("lseek(END - KRUN_FOOTER_LEN)");

            goto close_dev;
        }

        ret = read(fd, &footer[0], KRUN_FOOTER_LEN);
        if (ret != KRUN_FOOTER_LEN) {
            perror("read(KRUN_FOOTER_LEN)");

            goto close_dev;
        }

        if (memcmp(&footer[0], KRUN_MAGIC, 4) != 0) {
            printf("Couldn't find KRUN footer signature, falling back to SEV\n");
            return_str = sev_get_luks_passphrase(pass_len);

            goto close_dev;
        }

        tc_size = *(uint64_t *) &footer[4];

        if (lseek(fd, dev_size - tc_size - KRUN_FOOTER_LEN, SEEK_SET) == -1) {
            perror("lseek(END - tc_size - KRUN_FOOTER_LEN)");

            goto close_dev;
        }

        tc_json = malloc(tc_size + 1);
        if (tc_json == NULL) {
            perror("malloc(tc_size)");

            goto close_dev;
        }

        ret = read(fd, tc_json, tc_size);
        if (ret != tc_size) {
            perror("read(tc_size)");

            goto free_mem;
        }
        tc_json[tc_size] = '\0';

        /*
         * Parse the TEE config's workload_id and attestation_url field.
         */
        jsmn_init(&parser);

        tokens = (jsmntok_t *) malloc(sizeof(jsmntok_t) * MAX_TOKENS);\
        if (tokens == NULL) {
                perror("malloc(jsmntok_t)");

                goto free_mem;
        }

        num_tokens = jsmn_parse(&parser, tc_json, strlen(tc_json), tokens,
                MAX_TOKENS);
        if (num_tokens < 0) {
                printf("Unable to allocate JSON tokens\n");

                goto free_mem;
        } else if (num_tokens < 1 || tokens[0].type != JSMN_OBJECT) {
                printf("Unable to find object in TEE configuration file\n");

                goto free_mem;
        }

        wid_found = url_found = tee_found = tee_data_found = 0;

        for (int i = 1; i < num_tokens - 1; ++i) {
                tok_start = tc_json + tokens[i + 1].start;
                tok_end = tc_json + tokens[i + 1].end;
                tok_size = tok_end - tok_start;
                if (!jsoneq(tc_json, &tokens[i], "workload_id")) {
                        strncpy(wid, tok_start, tok_size);
                        wid_found = 1;
                } else if (!jsoneq(tc_json, &tokens[i], "attestation_url")) {
                        strncpy(url, tok_start, tok_size);
                        url_found = 1;
                } else if (!jsoneq(tc_json, &tokens[i], "tee")) {
                        strncpy(tee, tok_start, tok_size);
                        tee_found = 1;
                } else if (!jsoneq(tc_json, &tokens[i], "tee_data")) {
                        strncpy(tee_data, tok_start, tok_size);
                        tee_data_found = 1;
                }
        }

        if (!wid_found) {
                printf("Unable to find attestation workload ID\n");

                goto free_mem;
        } else if (!url_found) {
                printf("Unable to find attestation server URL\n");

                goto free_mem;
        } else if (!tee_found) {
                printf("Unable to find TEE generation server URL\n");

                goto free_mem;
        }

        if (strcmp(tee, "snp") == 0) {
                if (tee_data_found == 0) {
                        printf("Unable to find SNP generation\n");
                        goto free_mem;
                }

                return_str = snp_get_luks_passphrase(url, wid, tee_data, pass_len);
        } else if (strcmp(tee, "sev") == 0) {
                return_str = sev_get_luks_passphrase(pass_len);
        }

free_mem:
        free(tc_json);

close_dev:
        close(fd);

umount_dev:
        umount("/dev");

rmdir_dev:
        rmdir("/dev");

finish:
        return return_str;
}

static char *
snp_get_luks_passphrase(char *url, char *wid, char *tee_data, int *pass_len)
{
        char *pass;

        pass = (char *) malloc(MAX_PASS_SIZE);
        if (pass == NULL) {
                return NULL;
        }

        if (snp_attest(pass, url, wid, tee_data) == 0) {
                *pass_len = strlen(pass);
                return pass;
        }

        free(pass);

        return NULL;
}

static char *
sev_get_luks_passphrase(int *pass_len)
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

static int mount_filesystems()
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

	if (mount("devtmpfs", "/dev", "devtmpfs",
		  MS_RELATIME, NULL) < 0 && errno != EBUSY ) {
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

		if ((strcmp(env, "HOME") == 0) ||
		    (strcmp(env, "TERM") == 0)) {
			setenv(env, env_val, 1);
		} else {
			setenv(env, env_val, 0);
		}
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
	    strncasecmp(json + tok->start, s, tok->end - tok->start) == 0) {
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

		if (!parsed_entrypoint && jsoneq(data, &tokens[i], "Entrypoint") == 0 &&
			(i + 1) < num_tokens) {
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
		perror("Couldn't create timesync socket\n");
		return;
	}

	bzero((char *) &serveraddr, sizeof(serveraddr));
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
			perror("Error in timesync recv\n");
			return;
		} else if (n != 8) {
			printf("Ignoring bogus timesync packet\n");
			continue;
		}

		htime_ns = *(uint64_t *) &buf[0];
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

int reopen_fd(int fd, char *path, int flags)
{
    int newfd = open(path,flags);
    if (newfd < 0) {
        printf("Failed to open '%s': %s\n", path,strerror(errno));
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
    while ((entry=readdir(ports_dir))) {
        char* port_identifier = entry->d_name;
        int result_len = snprintf(path, sizeof(path), "/sys/class/virtio-ports/%s/name", port_identifier);

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
        } else if (port_name != NULL && strcmp(port_name, "krun-stdout\n") == 0) {
             snprintf(path, sizeof(path), "/dev/%s", port_identifier);
             reopen_fd(STDOUT_FILENO, path, O_WRONLY);
        } else if (port_name != NULL && strcmp(port_name, "krun-stderr\n") == 0) {
            snprintf(path, sizeof(path), "/dev/%s", port_identifier);
            reopen_fd(STDERR_FILENO, path, O_WRONLY);
        }
    }

    closedir(ports_dir);
    return 0;
}

int main(int argc, char **argv)
{
	struct ifreq ifr;
	int sockfd;
	char localhost[] = "localhost\0";
	char *hostname;
	char *krun_home;
	char *krun_term;
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
	if (mount_filesystems() < 0) {
		printf("Couldn't mount filesystems, bailing out\n");
		exit(-2);
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

#ifdef __TIMESYNC__
	if (fork() == 0) {
		clock_worker();
	}
#endif

    // We need to fork ourselves, because pid 1 cannot doesn't receive SIGINT signal
    int pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(-3);
    } if (pid == 0) { // child
        if (setup_redirects() < 0) {
           exit(-4);
        }
        if (execvp(exec_argv[0], exec_argv) < 0) {
            printf("Couldn't execute '%s' inside the vm: %s\n", exec_argv[0], strerror(errno));
            exit(-3);
        }
    } else { // parent
        // tell the kernel we don't want to be notified on SIGCHLD so it'll reap
        // our children for us
        signal(SIGCHLD, SIG_IGN);
        // wait for children since we can't exit init
        waitpid(pid, NULL, 0);
    }

	return 0;
}

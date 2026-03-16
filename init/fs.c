#include "fs.h"

static int try_mount(const char *source, const char *target, const char *fstype,
              unsigned long mountflags, const void *data);

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

static int try_mount(const char *source, const char *target, const char *fstype,
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


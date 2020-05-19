#include <inttypes.h>

struct KipConfig {
    uint8_t log_level;
    uint8_t num_vcpus;
    uint32_t ram_mib;
    const char *kernel;
    const char *root_dir;
    const char *exec_path;
    const char *args;
};

int kip_exec(struct KipConfig *config);

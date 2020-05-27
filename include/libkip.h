#include <inttypes.h>

struct KipConfig {
    /* Verbosity of the library, from 0=Off to 5=Trace. */
    uint8_t log_level;
    /* Number of vCPUs for the VM. */
    uint8_t num_vcpus;
    /* Amount of RAM for the VM. */
    uint32_t ram_mib;
    /* Path to the kernel ELF image. If NULL, use "/tmp/vmlinux.kip". */
    const char *kernel;
    /* Path to the init binary. If NULL, use "/tmp/init.kip". */
    const char *init;
    /* Directory to be used as root in the VM. */
    const char *root_dir;
    /* Path to the binary to be executed, relative to "root_dir". */
    const char *exec_path;
    /* Arguments to be passed to the binary. */
    const char *args;
   /*
    * Environment variables in KEY=VALUE format, separated by spaces. If NULL,
    * auto-generate a line collecting the variables present in the environment.
    */
    const char *env_line;
};

int kip_exec(struct KipConfig *config);

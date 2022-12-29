#include <inttypes.h>

/*
 * Sets the log level for the library.
 *
 * Arguments:
 *  "level" can be one of the following values:
 *    0: Off
 *    1: Error
 *    2: Warn
 *    3: Info
 *    4: Debug
 *    5: Trace
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_log_level(uint32_t level);

/*
 * Creates a configuration context.
 *
 * Returns:
 *  The context ID on success or a negative error number on failure.
 */
int32_t krun_create_ctx();

/*
 * Frees an existing configuration context.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_free_ctx(uint32_t ctx_id);

/*
 * Sets the basic configuration parameters for the microVM.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "num_vcpus" - the number of vCPUs.
 *  "ram_mib"   - the amount of RAM in MiB.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_vm_config(uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);

/*
 * Sets the path to be use as root for the microVM. Not available in libkrun-SEV.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "root_path" - a null-terminated string representing the path to be used as root.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_root(uint32_t ctx_id, const char *root_path);

/*
 * Sets the path to the disk image that contains the file-system to be used as root for the microVM.
 * The only supported image format is "raw". Only available in libkrun-SEV.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "disk_path" - a null-terminated string representing the path leading to the disk image that
 *                contains the root file-system.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_root_disk(uint32_t ctx_id, const char *disk_path);

/*
 * Sets the path to the disk image that contains the file-system to be used as a data partition for the microVM.
 * The only supported image format is "raw". Only available in libkrun-SEV.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "disk_path" - a null-terminated string representing the path leading to the disk image that
 *                contains the root file-system.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_data_disk(uint32_t ctx_id, const char *disk_path);

/*
 * Configures the mapped volumes for the microVM. Only supported on macOS, on Linux use
 * user_namespaces and bind-mounts instead. Not available in libkrun-SEV.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "mapped_volumes" - an array of string pointers with format "host_path:guest_path" representing
 *                     the volumes to be mapped inside the microVM
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_mapped_volumes(uint32_t ctx_id, char *const mapped_volumes[]);

/*
 * Configures a map of host to guest TCP ports for the microVM.
 *
 * Arguments:
 *  "ctx_id"   - the configuration context ID.
 *  "port_map" - an array of string pointers with format "host_port:guest_port"
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 *
 * Notes:
 *  Passing NULL (or not calling this function) as "port_map" has a different meaning than
 *  passing an empty array. The first one will instruct libkrun to attempt to expose all
 *  listening ports in the guest to the host, while the second means that no port from
 *  the guest will be exposed to host.
 *
 *  Exposed ports will only become accessible by their "host_port" in the guest too. This
 *  means that for a map such as "8080:80", applications running inside the guest will also
 *  need to access the service through the "8080" port.
 *
 */
int32_t krun_set_port_map(uint32_t ctx_id, char *const port_map[]);

/*
 * Configures a map of rlimits to be set in the guest before starting the isolated binary.
 *
 * Arguments:
 *  "ctx_id"  - the configuration context ID.
 *  "rlimits" - an array of string pointers with format "RESOURCE=RLIM_CUR:RLIM_MAX".
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_rlimits(uint32_t ctx_id, char *const rlimits[]);

/*
 * Sets the working directory for the executable to be run inside the microVM.
 *
 * Arguments:
 *  "ctx_id"        - the configuration context ID.
 *  "workdir_path"  - the path to the working directory, relative to the root configured with
 *                    "krun_set_root".
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_workdir(uint32_t ctx_id,
                         const char *workdir_path);

/*
 * Sets the path to the executable to be run inside the microVM, the arguments to be passed to the
 * executable, and the environment variables to be configured in the context of the executable.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "exec_path" - the path to the executable, relative to the root configured with "krun_set_root".
 *  "argv"      - an array of string pointers to be passed as arguments.
 *  "envp"      - an array of string pointers to be injected as environment variables into the
 *                context of the executable. If NULL, it will auto-generate an array collecting the
 *                the variables currently present in the environment.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_exec(uint32_t ctx_id,
                      const char *exec_path,
                      char *const argv[],
                      char *const envp[]);

/*
 * Sets environment variables to be configured in the context of the executable.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "envp"      - an array of string pointers to be injected as environment variables into the
 *                context of the executable. If NULL, it will auto-generate an array collecting the
 *                the variables currently present in the environment.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_env(uint32_t ctx_id, char *const envp[]);

/*
 * Sets the file path to the TEE configuration file. Only available in libkrun-sev.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "filepath"  - a null-terminated string representing file path to the TEE config file.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_tee_config_file(uint32_t ctx_id, const char *filepath);

/*
 * Starts and enters the microVM with the configured parameters. The VMM will attempt to take over
 * stdin/stdout to manage them on behalf of the process running inside the isolated environment,
 * simulating that the latter has direct control of the terminal.
 *
 * This function consumes the configuration pointed by the context ID.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *
 * Returns:
 *  This function only returns if an error happens before starting the microVM. Otherwise, the
 *  VMM assumes it has full control of the process, and will call to exit() once the microVM shuts
 *  down.
 */
int32_t krun_start_enter(uint32_t ctx_id);

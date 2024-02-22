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
 * NO LONGER SUPPORTED. DO NOT USE.
 *
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
 * Adds an independent virtio-fs device pointing to a host's directory with a tag.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "c_tag"          - tag to identify the filesystem in the guest.
 *  "c_path"         - full path to the directory in the host to be exposed to the guest.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_virtiofs(uint32_t ctx_id,
                          const char *c_tag,
                          const char *c_path);

/*
 * Configures the networking to use passt.
 * Call to this function disables TSI backend to use passt instead.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "fd"             - a file descriptor to communicate with passt
 *
 * Notes:
 * If you never call this function, networking uses the TSI backend.
 * This function should be called before krun_set_port_map.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_passt_fd(uint32_t ctx_id, int fd);

/*
 * Configures the networking to use gvproxy in vfkit mode.
 * Call to this function disables TSI backend to use gvproxy instead.
 *
 * Arguments:
 *  "ctx_id"  - the configuration context ID.
 *  "c_path"  - a null-terminated string representing the path for
 *              gvproxy's listen-vfkit unixdgram socket.
 *
 * Notes:
 * If you never call this function, networking uses the TSI backend.
 * This function should be called before krun_set_port_map.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_gvproxy_path(uint32_t ctx_id, char* c_path);

/*
 * Sets the MAC address for the virtio-net device when using the passt backend.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "mac"            - MAC address as an array of 6 uint8_t entries.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_net_mac(uint32_t ctx_id, uint8_t *const c_mac);

/*
 * Configures a map of host to guest TCP ports for the microVM.
 *
 * Arguments:
 *  "ctx_id"   - the configuration context ID.
 *  "port_map" - an array of string pointers with format "host_port:guest_port"
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 *  Documented errors:
 *       -ENOTSUP when passt networking is used
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
 * If past networking mode is used (krun_set_passt_fd was called), port mapping is not supported
 * as an API of libkrun (but you can still do port mapping using command line arguments of passt)
 */
int32_t krun_set_port_map(uint32_t ctx_id, char *const port_map[]);

/* Flags for virglrenderer.  Copied from virglrenderer bindings. */
#define VIRGLRENDERER_USE_EGL            1 << 0
#define VIRGLRENDERER_THREAD_SYNC        1 << 1
#define VIRGLRENDERER_USE_GLX            1 << 2
#define VIRGLRENDERER_USE_SURFACELESS    1 << 3
#define VIRGLRENDERER_USE_GLES           1 << 4
#define VIRGLRENDERER_USE_EXTERNAL_BLOB  1 << 5
#define VIRGLRENDERER_VENUS              1 << 6
#define VIRGLRENDERER_NO_VIRGL           1 << 7
#define VIRGLRENDERER_USE_ASYNC_FENCE_CB 1 << 8
#define VIRGLRENDERER_RENDER_SERVER      1 << 9
#define VIRGLRENDERER_DRM                1 << 10
/*
 * Enables and configures a virtio-gpu device.
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "virgl_flags" - flags to pass to virglrenderer.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_gpu_options(uint32_t ctx_id, uint32_t virgl_flags);

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
 * Adds a port-path pairing for guest IPC with a process in the host.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "port"      - a vsock port that the guest will connect to for IPC.
 *  "filepath"  - a null-terminated string representing the path of the UNIX
 *                socket in the host.
 */
int32_t krun_add_vsock_port(uint32_t ctx_id,
                            uint32_t port,
                            const char *c_filepath);
/*
 * Returns the eventfd file descriptor to signal the guest to shut down orderly. This must be
 * called before starting the microVM with "krun_start_event". Only available in libkrun-efi.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *
 * Returns:
 *  The eventfd file descriptor or a negative error number on failure.
 */
int32_t krun_get_shutdown_eventfd(uint32_t ctx_id);


/*
 * Configures the console device to ignore stdin and write the output to "c_filepath".
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "filepath"  - a null-terminated string representing the path of the file to write the
 *                console output.
 */
int32_t krun_set_console_output(uint32_t ctx_id, const char *c_filepath);

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

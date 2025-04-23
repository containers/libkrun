#ifndef _LIBKRUN_H
#define _LIBKRUN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>

/**
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

/**
 * Creates a configuration context.
 *
 * Returns:
 *  The context ID on success or a negative error number on failure.
 */
int32_t krun_create_ctx();

/**
 * Frees an existing configuration context.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_free_ctx(uint32_t ctx_id);

/**
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

/**
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

/**
 * DEPRECATED. Use krun_add_disk instead.
 *
 * Sets the path to the disk image that contains the file-system to be used as root for the microVM.
 * The only supported image format is "raw".
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

/**
 * DEPRECATED. Use krun_add_disk instead.
 *
 * Sets the path to the disk image that contains the file-system to be used as
 * a data partition for the microVM.  The only supported image format is "raw".
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

/**
 * Adds a disk image to be used as a general partition for the microVM. The only supported image
 * format is "raw".
 *
 * This API is mutually exclusive with the deprecated krun_set_root_disk and
 * krun_set_data_disk methods and must not be used together.
 *
 * This function deliberately only handles images in the Raw format, because it doesn't allow
 * specifying an image format, and probing an image's format is dangerous. For more information,
 * see the security note on `krun_add_disk2`, which allows opening non-Raw images.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "block_id"  - a null-terminated string representing the partition.
 *  "disk_path" - a null-terminated string representing the path leading to the disk image.
 *  "read_only" - whether the mount should be read-only. Required if the caller does not have
 *                write permissions (for disk images in /usr/share).
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_disk(uint32_t ctx_id, const char *block_id, const char *disk_path, bool read_only);

/* Supported disk image formats */
#define KRUN_DISK_FORMAT_RAW 0
#define KRUN_DISK_FORMAT_QCOW2 1
/**
 * Adds a disk image to be used as a general partition for the microVM. The supported
 * image formats are: "raw" and "qcow2".
 *
 * This API is mutually exclusive with the deprecated krun_set_root_disk and
 * krun_set_data_disk methods and must not be used together.
 *
 * SECURITY NOTE:
 * Non-Raw images can reference other files, which libkrun will automatically open, and to which the
 * guest will have access. Libkrun should therefore never be asked to open an image in a non-Raw
 * format when it doesn't come from a fully trustworthy source.
 *
 * Consequently, probing an image's format is quite dangerous and to be avoided if at all possible,
 * which is why libkrun provides no facilities for doing so. If it's not clear what format an image
 * has, it may also not be clear whether it can be trusted to not reference files to which the guest
 * shouldn't have access.
 *
 * If probing absolutely can't be avoided, it must only be done on images that are fully trusted, i.e.
 * before a potentially untrusted guest had write access to it. Specifically, consider that a guest has
 * full access to all of a Raw image, and can therefore turn it into a file in an arbitrary format, for
 * example, into a Qcow2 image, referencing and granting a malicious guest access to arbitrary files.
 * To hand a Raw image to an untrusted and potentially malicious guest, and then to re-probe it after
 * the guest was able to write to it (when it can no longer be trusted), would therefore be a severe
 * security vulnerability.
 *
 * Therefore, after having probed a yet fully trusted image once, the result must be remembered so the
 * image will from then on always be opened in the format that was detected originally. When adhering
 * to this, a guest can write anything they want to a Raw image, it's always going to be opened as a
 * Raw image, preventing the security vulnerability outlined above.
 *
 * However, if at all possible, the image format should be explicitly selected based on knowledge
 * obtained separately from the pure image data, for example by the user.
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "block_id"    - a null-terminated string representing the partition.
 *  "disk_path"   - a null-terminated string representing the path leading to the disk image.
 *  "disk_format" - the disk image format (i.e. KRUN_DISK_FORMAT_{RAW, QCOW2})
 *  "read_only"   - whether the mount should be read-only. Required if the caller does not have
 *                  write permissions (for disk images in /usr/share).
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_disk2(uint32_t ctx_id,
                       const char *block_id,
                       const char *disk_path,
                       uint32_t disk_format,
                       bool read_only);

/**
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
int32_t krun_set_mapped_volumes(uint32_t ctx_id, const char *const mapped_volumes[]);

/**
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

/**
 * Adds an independent virtio-fs device pointing to a host's directory with a tag. This
 * variant allows specifying the size of the DAX window.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "c_tag"          - tag to identify the filesystem in the guest.
 *  "c_path"         - full path to the directory in the host to be exposed to the guest.
 *  "shm_size"       - size of the DAX SHM window in bytes.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_virtiofs2(uint32_t ctx_id,
                           const char *c_tag,
                           const char *c_path,
                           uint64_t shm_size);

/**
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

/**
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
int32_t krun_set_gvproxy_path(uint32_t ctx_id, char *c_path);

/**
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

/**
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
int32_t krun_set_port_map(uint32_t ctx_id, const char *const port_map[]);

/* Flags for virglrenderer.  Copied from virglrenderer bindings. */
#define VIRGLRENDERER_USE_EGL 1 << 0
#define VIRGLRENDERER_THREAD_SYNC 1 << 1
#define VIRGLRENDERER_USE_GLX 1 << 2
#define VIRGLRENDERER_USE_SURFACELESS 1 << 3
#define VIRGLRENDERER_USE_GLES 1 << 4
#define VIRGLRENDERER_USE_EXTERNAL_BLOB 1 << 5
#define VIRGLRENDERER_VENUS 1 << 6
#define VIRGLRENDERER_NO_VIRGL 1 << 7
#define VIRGLRENDERER_USE_ASYNC_FENCE_CB 1 << 8
#define VIRGLRENDERER_RENDER_SERVER 1 << 9
#define VIRGLRENDERER_DRM 1 << 10
/**
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

/**
 * Enables and configures a virtio-gpu device. This variant allows specifying
 * the size of the host window (acting as vRAM in the guest).
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "virgl_flags" - flags to pass to virglrenderer.
 *  "shm_size"    - size of the SHM host window in bytes.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_gpu_options2(uint32_t ctx_id,
                              uint32_t virgl_flags,
                              uint64_t shm_size);

/**
 * Enables or disables a virtio-snd device.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *  "enable" - boolean indicating whether virtio-snd should be enabled or disabled.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_snd_device(uint32_t ctx_id, bool enable);

/**
 * Configures a map of rlimits to be set in the guest before starting the isolated binary.
 *
 * Arguments:
 *  "ctx_id"  - the configuration context ID.
 *  "rlimits" - an array of string pointers with format "RESOURCE=RLIM_CUR:RLIM_MAX".
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_rlimits(uint32_t ctx_id, const char *const rlimits[]);

/**
 * Sets the SMBIOS OEM Strings.
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "oem_strings" - an array of string pointers. Must be terminated with an additional NULL pointer.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_smbios_oem_strings(uint32_t ctx_id, const char *const oem_strings[]);

/**
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

/**
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
                      const char *const argv[],
                      const char *const envp[]);

#define KRUN_KERNEL_FORMAT_RAW 0
#define KRUN_KERNEL_FORMAT_ELF 1
#define KRUN_KERNEL_FORMAT_PE_GZ 2
#define KRUN_KERNEL_FORMAT_IMAGE_BZ2 3
#define KRUN_KERNEL_FORMAT_IMAGE_GZ 4
#define KRUN_KERNEL_FORMAT_IMAGE_ZSTD 5
/**
 * Sets the path to the kernel to be loaded in the microVM.
 *
 * Arguments:
 *  "ctx_id"        - the configuration context ID.
 *  "kernel_path"   - the path to the kernel, relative to the host's filesystem.
 *  "kernel_format" - the kernel format.
 *  "initramfs"     - the path to the initramfs, relative to the host's filesystem.
 *  "cmdline"       - the kernel command line.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_kernel(uint32_t ctx_id,
                        const char *kernel_path,
                        uint32_t kernel_format,
                        const char *initramfs,
                        const char *cmdline);

/**
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
int32_t krun_set_env(uint32_t ctx_id, const char *const envp[]);

/**
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

/**
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

/**
 * Adds a port-path pairing for guest IPC with a process in the host.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "port"      - a vsock port that the guest will connect to for IPC.
 *  "filepath"  - a null-terminated string representing the path of the UNIX
 *                socket in the host.
 *  "listen"    - true if guest expects connections to be initiated from host side
 */
int32_t krun_add_vsock_port2(uint32_t ctx_id,
                             uint32_t port,
                             const char *c_filepath,
                             bool listen);
/**
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

/**
 * Configures the console device to ignore stdin and write the output to "c_filepath".
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "filepath"  - a null-terminated string representing the path of the file to write the
 *                console output.
 */
int32_t krun_set_console_output(uint32_t ctx_id, const char *c_filepath);

/**
 * Configures uid which is set right before the microVM is started.
 *
 * This is useful for example when you want to access host block devices
 * from the microVM which requires root privileges when opening the device
 * but you don't want to run the whole microVM as root.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "uid"            - a user id to be set.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_setuid(uint32_t ctx_id, uid_t uid);

/**
 * Configures gid which is set right before the microVM is started.
 *
 * This is useful for example when you want to access host block devices
 * from the microVM which requires root privileges when opening the device
 * but you don't want to run the whole microVM as root.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "gid"            - a group id to be set.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_setgid(uint32_t ctx_id, gid_t gid);

/**
 * Configures the microVM to support Nested Virtualization
 *
 * Arguments:
 *  "ctx_id"  - the configuration context ID.
 *  "enabled" - true to enable Nested Virtualization in the microVM.
 *
 * Notes:
 *  This feature is only supported on macOS.
 *
 * Returns:
 *  Zero on success or a negative error number on failure. Success doesn't imply that
 *  Nested Virtualization is supported on the system, only that it's going to be requested
 *  when the microVM is created after calling "krun_start_enter".
 */
int32_t krun_set_nested_virt(uint32_t ctx_id, bool enabled);

/**
 * Check the system if Nested Virtualization is supported
 *
 * Notes:
 *  This feature is only supported on macOS.
 *
 * Returns:
 *  - 1 : Success and Nested Virtualization is supported
 *  - 0 : Success and Nested Virtualization is not supported
 *  - <0: Failure
 */
int32_t krun_check_nested_virt(void);

/**
 * Specify whether to split IRQCHIP responsibilities between the host and the guest.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *  "enable" - whether to enable the split IRQCHIP
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
*/
int32_t krun_split_irqchip(uint32_t ctx_id, bool enable);

/**
 * Starts and enters the microVM with the configured parameters. The VMM will attempt to take over
 * stdin/stdout to manage them on behalf of the process running inside the isolated environment,
 * simulating that the latter has direct control of the terminal.
 *
 * This function consumes the configuration pointed by the context ID.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *
 * Notes:
 *  This function only returns if an error happens before starting the microVM. Otherwise, the
 *  VMM assumes it has full control of the process, and will call to exit() with the workload's exit
 *  code once the microVM shuts down. If an error occurred before running the workload the process 
 *  will exit() with an error exit code.
 * 
 * Error exit codes:
 *  125     - "init" cannot set up the environment inside the microVM.
 *  126     - "init" can find the executable to be run inside the microVM but cannot execute it.
 *  127     - "init" cannot find the executable to be run inside the microVM.
 *
 * Returns:
 *  -EINVAL - The VMM has detected an error in the microVM configuration.
 */
int32_t krun_start_enter(uint32_t ctx_id);

#ifdef __cplusplus
}
#endif

#endif // _LIBKRUN_H

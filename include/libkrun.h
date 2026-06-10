#ifndef LIBKRUN_H
#define LIBKRUN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef void* KrunError;
typedef void* KrunMmioDeviceManager;
typedef void* KrunFsDevice;
typedef void* KrunConsoleDevice;
typedef void* KrunConsoleBuilder;
typedef void* KrunBalloonDevice;
typedef void* KrunRngDevice;
typedef void* KrunPayload;
typedef void* KrunVmmBuilder;
typedef void* KrunVmm;
typedef void* KrunAttachDevice; /* KrunFsDevice | KrunConsoleDevice | KrunBalloonDevice | KrunRngDevice */
typedef void* KrunError; /* KrunError | KrunVtableError */
typedef void* KrunPushStr; /* KrunVtablePushStr */

#ifndef KRUN_PRIMITIVES_DEFINED
#define KRUN_PRIMITIVES_DEFINED

typedef void* KrunObject; /* KrunError | KrunMmioDeviceManager | KrunFsDevice | KrunConsoleDevice | KrunConsoleBuilder | KrunBalloonDevice | KrunRngDevice | KrunPayload | KrunVmmBuilder | KrunVmm */

typedef uint64_t KrunResult;
#define KRUN_RESULT_SUCCESS 0

/* Caller must ensure data is valid UTF-8 */
typedef struct {
    const char* data;
    size_t len;
} KrunStr;

typedef struct {
    const uint8_t* data;
    size_t len;
} KrunBytes;

#define KRUN_STR(s) ((KrunStr){ .data = (s), .len = (s) ? strlen(s) : 0 })
#if defined(__GNUC__)
#define KRUN_BYTES(arr) ({ \
    _Static_assert( \
        !__builtin_types_compatible_p(typeof(arr), typeof(&(arr)[0])), \
        "KRUN_BYTES() requires an array, not a pointer"); \
    ((KrunBytes){ .data = (const uint8_t*)(arr), .len = sizeof(arr) }); \
})
#else
#define KRUN_BYTES(arr) \
    ((KrunBytes){ .data = (const uint8_t*)(arr), .len = sizeof(arr) })
#endif

/**
 * Stack-allocated temporary handle for passing vtable-based objects.
 * Only valid for the duration of the call — the callee borrows, not owns.
 */
typedef struct {
    uint32_t type_tag;
    uint32_t metadata;
    const void *vtable_ptr;
    const void *user_data;
    uint16_t vtable_size;
} KrunVtableHandle;

#define KRUN_VTABLE_HANDLE(tag, vtable, self_data) \
    ((KrunVtableHandle){ .type_tag = (tag), .metadata = 0, \
      .vtable_ptr = &(vtable), .user_data = (self_data), \
      .vtable_size = sizeof(vtable) })

/**
 * Opaque 16-byte handle entry in an object array.
 * Do not access fields directly — pass &entry to typed methods.
 * Do NOT pass individual entries to destroy.
 */
typedef struct {
    uint32_t _tag;
    uint32_t _meta;
    const void* _ptr;
} KrunObjectArrayEntry;

/**
 * Contiguous array of borrowed handles.
 * Returned by methods that produce slices of handles.
 * Individual elements must NOT be passed to destroy —
 * call free_object_array() to free the entire array.
 */
typedef struct {
    const KrunObjectArrayEntry* items;
    size_t len;
} KrunObjectArray;

#define KRUN_OBJECT_ARRAY_GET(arr, i) \
    (assert((size_t)(i) < (arr).len), (KrunObject)(void*)&(arr).items[(i)])

#endif /* KRUN_PRIMITIVES_DEFINED */

/* Free an owned string returned by the library */
void krun_str_free(KrunStr s);

/* Free an object array returned by the library */
void krun_free_object_array(KrunObjectArray a);


/* KernelFormat ------------------------------------------------------ */

#define KRUN_KERNEL_FORMAT_ELF 0
#define KRUN_KERNEL_FORMAT_RAW 1

/* LogLevel ---------------------------------------------------------- */

#define KRUN_LOG_LEVEL_OFF 0
#define KRUN_LOG_LEVEL_ERROR 1
#define KRUN_LOG_LEVEL_WARN 2
#define KRUN_LOG_LEVEL_INFO 3
#define KRUN_LOG_LEVEL_DEBUG 4
#define KRUN_LOG_LEVEL_TRACE 5

/* LogStyle ---------------------------------------------------------- */

#define KRUN_LOG_STYLE_AUTO 0
#define KRUN_LOG_STYLE_ALWAYS 1
#define KRUN_LOG_STYLE_NEVER 2

/* LogTarget --------------------------------------------------------- */

#define KRUN_LOG_TARGET_DEFAULT 0
#define KRUN_LOG_TARGET_STDOUT 1
#define KRUN_LOG_TARGET_STDERR 2

/* Error ------------------------------------------------------------- */

#define KRUN_ERROR__INVALID_PARAM ((uint64_t)16777229 << 32 | 100)
#define KRUN_ERROR__DUPLICATE_DEVICE ((uint64_t)16777229 << 32 | 101)
#define KRUN_ERROR__DEVICE_LIMIT_EXCEEDED ((uint64_t)16777229 << 32 | 102)
#define KRUN_ERROR__MISSING_CONFIG ((uint64_t)16777229 << 32 | 103)
#define KRUN_ERROR__CONFLICTING_CONFIG ((uint64_t)16777229 << 32 | 104)
#define KRUN_ERROR__OUT_OF_RANGE ((uint64_t)16777229 << 32 | 105)
#define KRUN_ERROR__FILE_NOT_FOUND ((uint64_t)16777229 << 32 | 200)
#define KRUN_ERROR__PERMISSION_DENIED ((uint64_t)16777229 << 32 | 201)
#define KRUN_ERROR__RESOURCE_ALLOC ((uint64_t)16777229 << 32 | 202)
#define KRUN_ERROR__BAD_FD ((uint64_t)16777229 << 32 | 203)
#define KRUN_ERROR__BACKEND_UNAVAILABLE ((uint64_t)16777229 << 32 | 300)
#define KRUN_ERROR__FEATURE_DISABLED ((uint64_t)16777229 << 32 | 301)
#define KRUN_ERROR__DISK_FORMAT_ERROR ((uint64_t)16777229 << 32 | 302)
#define KRUN_ERROR__ALREADY_STARTED ((uint64_t)16777229 << 32 | 400)
#define KRUN_ERROR__VALIDATION_FAILED ((uint64_t)16777229 << 32 | 401)
#define KRUN_ERROR__HYPERVISOR_ERROR ((uint64_t)16777229 << 32 | 402)
#define KRUN_ERROR__BOOT_ERROR ((uint64_t)16777229 << 32 | 403)
#define KRUN_ERROR__INTERNAL ((uint64_t)16777229 << 32 | 900)

/* MmioDeviceManager ------------------------------------------------- */

/** Create an empty device manager. */
KrunMmioDeviceManager krun_mmio_device_manager_new();
/**
 * Add a device to this manager.
 *
 * Devices are attached in the order they are added. The device must
 * implement [`AttachDevice`] — all built-in device types
 * (`FsDevice`, `ConsoleDevice`, etc.) implement this trait.
 */
void krun_mmio_device_manager_add(KrunMmioDeviceManager handle, KrunAttachDevice device);
void krun_mmio_device_manager_destroy(KrunMmioDeviceManager handle);

/* FsDevice ---------------------------------------------------------- */

/**
 * Create a new virtiofs device sharing a host directory.
 *
 * # Arguments
 *
 * - `tag`: the filesystem tag visible to the guest (e.g. `"/dev/root"`).
 * - `host_path`: the host directory to share.
 */
KrunFsDevice krun_fs_device_new(KrunStr tag, KrunStr host_path, KrunError* err_out);
/** Create a read-only virtiofs device sharing a host directory. */
KrunFsDevice krun_fs_device_new_read_only(KrunStr tag, KrunStr host_path, KrunError* err_out);
/**
 * Create a virtiofs device with no host directory (NullFs).
 *
 * The guest sees an empty filesystem. Use
 * [`add_overlay_dir`](Self::add_overlay_dir) and
 * [`add_overlay_file`](Self::add_overlay_file) to populate it
 * with virtual entries.
 */
KrunFsDevice krun_fs_device_new_null(KrunStr tag, KrunError* err_out);
/**
 * Add a virtual directory overlay entry.
 *
 * `path` may contain `/` separators for nested entries (e.g.
 * `"etc/nested"`). Intermediate directories must already exist.
 */
void krun_fs_device_add_overlay_dir(KrunFsDevice handle, KrunStr path, uint32_t mode);
/**
 * Add a virtual file overlay entry.
 *
 * `path` may contain `/` separators for nested entries (e.g.
 * `"etc/nested/deep.txt"`). Intermediate directories must already
 * exist.
 */
void krun_fs_device_add_overlay_file(KrunFsDevice handle, KrunStr path, KrunBytes data, uint32_t mode, bool one_shot);
void krun_fs_device_destroy(KrunFsDevice handle);

/* ConsoleDevice ----------------------------------------------------- */

/** Create a new console builder. */
KrunConsoleBuilder krun_console_device_builder();
void krun_console_device_destroy(KrunConsoleDevice handle);

/* ConsoleBuilder ---------------------------------------------------- */

/**
 * Add a TTY-backed port to the console.
 *
 * If the fd refers to a real terminal, raw mode will be enabled on it
 * when the VM starts, and restored on shutdown.
 *
 * # Arguments
 *
 * - `name`: the port name visible to the guest (e.g. `"tty0"`).
 * - `tty_fd`: borrowed fd for the host TTY; duplicated internally, caller retains ownership.
 *
 * # Returns
 *
 * The zero-based port index, usable with [`set_kernel_console`](ConsoleBuilder::set_kernel_console).
 */
KrunResult krun_console_builder_add_tty_port(KrunConsoleBuilder handle, KrunStr name, int tty_fd, uint32_t* result, KrunError* err_out);
/**
 * Designate a port as the kernel console (`console=hvcN`).
 *
 * # Arguments
 *
 * - `port_index`: a value returned by [`add_tty_port`](ConsoleBuilder::add_tty_port).
 */
KrunResult krun_console_builder_set_kernel_console(KrunConsoleBuilder handle, uint32_t port_index, KrunError* err_out);
/** Build the console device. At least one port must have been added. */
KrunConsoleDevice krun_console_builder_build(KrunConsoleBuilder handle, KrunError* err_out);
/**
 * Set up the default console: port 0 (hvc0) plus named redirect ports.
 *
 * Replicates the v1 `krun_add_virtio_console_default` behaviour:
 *
 * - If any fd is a terminal, port 0 becomes a full TTY console
 *   (raw mode enabled), and that fd is NOT added as a redirect port.
 * - Otherwise, port 0 gets log output and named redirect ports
 *   (`krun-stdin`, `krun-stdout`, `krun-stderr`) are added.
 *
 * Pass `None` to skip a stream.
 */
KrunResult krun_console_builder_add_default_console(KrunConsoleBuilder handle, int stdin, int stdout, int stderr, KrunError* err_out);
void krun_console_builder_destroy(KrunConsoleBuilder handle);

/* BalloonDevice ----------------------------------------------------- */

/** Create a new balloon device. */
KrunBalloonDevice krun_balloon_device_new(KrunError* err_out);
void krun_balloon_device_destroy(KrunBalloonDevice handle);

/* RngDevice --------------------------------------------------------- */

/** Create a new RNG device. */
KrunRngDevice krun_rng_device_new(KrunError* err_out);
void krun_rng_device_destroy(KrunRngDevice handle);

/* Payload ----------------------------------------------------------- */

/** Load the built-in krunfw kernel. */
KrunPayload krun_payload_load_krunfw(KrunError* err_out);
/** Load an external kernel (Linux, FreeBSD, etc.). */
KrunPayload krun_payload_load_external(KrunStr path, uint32_t format, KrunStr cmdline, KrunError* err_out);
/** The kernel cmdline (base + any appended fragments). */
KrunStr krun_payload_cmdline(KrunPayload handle);
/** Append a fragment to the kernel cmdline. */
void krun_payload_append_cmdline(KrunPayload handle, KrunStr extra);
void krun_payload_destroy(KrunPayload handle);

/* VmmBuilder -------------------------------------------------------- */

/** Create a new VM builder with no configuration. */
KrunVmmBuilder krun_vmm_builder_new();
/** Set the number of virtual CPUs. Must be at least 1. */
KrunResult krun_vmm_builder_vcpus(KrunVmmBuilder* handle, uint8_t count, KrunError* err_out);
/** Set the amount of guest RAM in mebibytes. Must be at least 1. */
KrunResult krun_vmm_builder_ram_mib(KrunVmmBuilder* handle, uint32_t mib, KrunError* err_out);
/**
 * Set the kernel to boot.
 *
 * Pass a [`Payload`] obtained from
 * [`Payload::load_krunfw()`] or
 * [`Payload::load_external()`].
 */
void krun_vmm_builder_kernel(KrunVmmBuilder* handle, KrunPayload kernel);
/**
 * Set the device manager containing all virtio devices.
 *
 * The device manager determines which transport bus is used (currently
 * only [`MmioDeviceManager`] for virtio-mmio).
 */
void krun_vmm_builder_devices(KrunVmmBuilder* handle, KrunMmioDeviceManager devices);
/**
 * Build the VM, creating guest memory, attaching devices, and starting
 * vCPUs. All required fields (`vcpus`, `ram_mib`, `kernel`, `devices`)
 * must have been set.
 */
KrunVmm krun_vmm_builder_build(KrunVmmBuilder* handle, KrunError* err_out);
void krun_vmm_builder_destroy(KrunVmmBuilder handle);

/* Vmm --------------------------------------------------------------- */

/**
 * Run the VM event loop. This call blocks until the VM exits or a
 * fatal error occurs.
 */
void krun_vmm_run(KrunVmm handle);
void krun_vmm_destroy(KrunVmm handle);

/* KrunPushStrVtable ------------------------------------------------- */

#define KRUN_PUSH_STR_TYPE_TAG 16777228

typedef struct {
    void (*drop)(void* self_data);
    bool (*push)(void* self_data, KrunStr s);
} KrunPushStrVtable;

/* PushStr (dispatch) ------------------------------------------------ */

bool krun_push_str_push(KrunPushStr handle, KrunStr s);
void krun_push_str_destroy(KrunPushStr handle);

/* KrunErrorVtable --------------------------------------------------- */

#define KRUN_ERROR_TYPE_TAG 16777229

typedef struct {
    void (*drop)(void* self_data);
    uint32_t (*code)(void* self_data);
    void (*message)(void* self_data, KrunPushStr writer);
    uint64_t (*result)(void* self_data);
} KrunErrorVtable;

/* Error (dispatch) -------------------------------------------------- */

uint32_t krun_error_code(KrunError handle);
void krun_error_message(KrunError handle, KrunPushStr writer);
uint64_t krun_error_result(KrunError handle);
void krun_error_destroy(KrunError handle);
uint32_t krun_error_code(KrunError handle);
void krun_error_message(KrunError handle, KrunPushStr writer);

/* Free functions ---------------------------------------------------- */

KrunResult krun_init_log(uint32_t target, uint32_t level, uint32_t style, KrunError* err_out);
KrunStr krun_result_name(KrunResult r);
const char* krun_result_name_cstr(KrunResult r);

#endif /* LIBKRUN_H */

/*
 * Chroot-like functionality with libkrun.
 *
 * Usage: chroot_vm NEWROOT COMMAND [ARGS...]
 *
 * Executes COMMAND inside a lightweight VM with NEWROOT as the rootfs.
 *
 * Build (after generating the header):
 *   cargo run -p libkrun-cdylib --bin gen-libkrun-header > include/libkrun.h
 *   cc -o chroot_vm examples/chroot_vm.c -Iinclude -Ltarget/debug -l:libkrun.so
 */

#include <libkrun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Error handling with ffier's PushStr trait.
 *
 * krun_error_message() writes the error's Display message into a PushStr
 * writer — a callback-based sink (like Rust's fmt::Write). Here we use a
 * trivial writer that prints directly to stderr.
 *
 * Other approaches:
 *  - Buffer into a malloc'd NUL-terminated string (implement push() to
 *    realloc and append, then use the resulting char* with printf/syslog).
 *  - If you only need the numeric error code, use krun_error_code(err).
 */

static bool push_to_stderr(void *userdata, KrunStr s)
{
    (void)userdata;
    fwrite(s.data, 1, s.len, stderr);
    return true;
}

static KrunVtableHandle stderr_writer = KRUN_VTABLE_HANDLE(
    KRUN_PUSH_STR_TYPE_TAG,
    ((KrunPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

/*
 * Caller must declare `KrunError err = NULL;` and pass `&err` as the
 * err_out parameter in the call.
 */
#define TRY(call)                                                         \
    err = NULL;                                                                \
    call;                                                                      \
    if (err) {                                                                 \
        flockfile(stderr);                                                    \
        fprintf(stderr, "%s failed: ", #call);                                \
        krun_error_message(err, &stderr_writer);                              \
        fputc('\n', stderr);                                                \
        funlockfile(stderr);                                                  \
        krun_error_destroy(err);                                              \
        return 1;                                                              \
    }

int main(int argc, char *const argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s NEWROOT COMMAND [ARGS...]\n", argv[0]);
        return 1;
    }

    const char *new_root = argv[1];
    const char *guest_cmd = argv[2];
    KrunError err = NULL;

    TRY(krun_init_log(KRUN_LOG_TARGET_DEFAULT, KRUN_LOG_LEVEL_WARN,
                           KRUN_LOG_STYLE_AUTO, &err));

    TRY(KrunFsDevice rootfs =
            krun_fs_device_new(KRUN_STR("/dev/root"), KRUN_STR(new_root),
                               &err));

    KrunConsoleBuilder console_builder = krun_console_device_builder();
    KrunInitBuilder payload_builder =
        krun_init_builder(rootfs, console_builder);

    KrunStr guest_args[argc - 3];
    for (int i = 3; i < argc; i++)
        guest_args[i - 3] = KRUN_STR(argv[i]);

    TRY(krun_init_builder_exec(&payload_builder, KRUN_STR(guest_cmd),
                                    guest_args, argc - 3, &err));
    TRY(krun_init_builder_workdir(&payload_builder, KRUN_STR("/"),
                                       &err));

    KrunStr env[] = {KRUN_STR("HOME=/root"), KRUN_STR("TERM=xterm-256color")};
    TRY(krun_init_builder_env(&payload_builder, env, 2, &err));

    TRY(KrunInit payload =
                 krun_init_builder_build(&payload_builder, &err));

    TRY(KrunConsoleDevice console =
            krun_console_builder_build(console_builder, &err));

    TRY(KrunBalloonDevice balloon = krun_balloon_device_new(&err));
    TRY(KrunRngDevice rng = krun_rng_device_new(&err));

    KrunMmioDeviceManager devices = krun_mmio_device_manager_new();
    krun_mmio_device_manager_add(devices, rootfs);
    krun_mmio_device_manager_add(devices, console);
    krun_mmio_device_manager_add(devices, balloon);
    krun_mmio_device_manager_add(devices, rng);

    KrunVmmBuilder builder = krun_vmm_builder_new();
    TRY(krun_vmm_builder_vcpus(&builder, 2, &err));
    TRY(krun_vmm_builder_ram_mib(&builder, 512, &err));
    krun_vmm_builder_payload(&builder, payload);
    krun_vmm_builder_devices(&builder, devices);

    TRY(KrunVmm vmm =
            krun_vmm_builder_build(&builder, &err));

    krun_vmm_run(vmm);
    krun_vmm_destroy(vmm);
    return 0;
}

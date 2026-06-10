/*
 * Chroot-like functionality with libkrun.
 *
 * Usage: chroot_vm NEWROOT COMMAND [ARGS...]
 *
 * Executes COMMAND inside a lightweight VM with NEWROOT as the rootfs.
 *
 * Build (after installing the library):
 *   cc -o chroot_vm examples/chroot_vm.c -Iinclude -lkrun -lkrun_init
 */

#include <assert.h>
#include <libkrun.h>
#include <libkrun_init.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Error handling with ffier's PushStr trait.
 *
 * krun_error_message() writes the error's Display message into a PushStr
 * writer — a callback-based sink. Here we use a trivial writer that prints
 * directly to stderr.
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

#define TRY(call)                                                              \
    err = NULL;                                                                \
    call;                                                                      \
    if (err) {                                                                 \
        flockfile(stderr);                                                     \
        fprintf(stderr, "%s failed: ", #call);                                 \
        krun_error_message(err, &stderr_writer);                               \
        fputc('\n', stderr);                                                   \
        funlockfile(stderr);                                                   \
        krun_error_destroy(err);                                               \
        return 1;                                                              \
    }

int main(int argc, char *const argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s NEWROOT COMMAND [ARGS...]\n", argv[0]);
        return 1;
    }

    const char *new_root = argv[1];
    KrunError err = NULL;

    TRY(krun_init_log(KRUN_LOG_TARGET_DEFAULT, KRUN_LOG_LEVEL_WARN,
                       KRUN_LOG_STYLE_AUTO, &err));

    /* Build init config (uses init-blob library). */
    KrunInitConfigBuilder config_builder = krun_init_config_builder();

    KrunStr guest_args[argc - 2];
    for (int i = 2; i < argc; i++)
        guest_args[i - 2] = KRUN_STR(argv[i]);
    krun_init_config_builder_args(&config_builder, guest_args, argc - 2);

    KrunStr env[] = { KRUN_STR("HOME=/root"), KRUN_STR("TERM=xterm-256color") };
    krun_init_config_builder_env(&config_builder, env, 2);
    krun_init_config_builder_workdir(&config_builder, KRUN_STR("/"));

    KrunInitConfig config = krun_init_config_builder_build(&config_builder);

    /* Create rootfs. */
    TRY(KrunFsDevice rootfs =
            krun_fs_device_new(KRUN_STR("/dev/root"), KRUN_STR(new_root),
                               &err));

    /* Inject init files into rootfs.
     * TODO: Replace this loop + append_cmdline with a single
     * krun_apply_init_config(config, rootfs, kernel) call once ffier
     * supports cross-library function export. */
    KrunObjectArray files = krun_init_config_guest_files(config);
    for (size_t i = 0; i < files.len; i++) {
        KrunInitGuestFile gf = KRUN_OBJECT_ARRAY_GET(files, i);
        krun_fs_device_add_overlay_file(
            rootfs,
            krun_init_guest_file_path(gf),
            krun_init_guest_file_data(gf),
            krun_init_guest_file_mode(gf),
            krun_init_guest_file_one_shot(gf));
    }
    krun_free_object_array(files);

    /* Load kernel and apply init cmdline. */
    TRY(KrunPayload kernel = krun_payload_load_krunfw(&err));
    krun_payload_append_cmdline(kernel,
                                krun_init_config_kernel_cmdline(config));

    /* Console: default ports (hvc0 + stdin/stdout/stderr redirects). */
    KrunConsoleBuilder console_builder = krun_console_device_builder();
    TRY(krun_console_builder_add_default_console(console_builder,
                                                  STDIN_FILENO, STDOUT_FILENO,
                                                  STDERR_FILENO, &err));
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
    krun_vmm_builder_kernel(&builder, kernel);
    krun_vmm_builder_devices(&builder, devices);

    TRY(KrunVmm vmm = krun_vmm_builder_build(&builder, &err));

    krun_vmm_run(vmm);
    krun_vmm_destroy(vmm);
    krun_init_config_destroy(config);
    return 0;
}

//! Chroot-like functionality with libkrun.
//!
//! Usage: chroot_vm NEWROOT COMMAND [ARGS...]
//!
//! Executes COMMAND inside a lightweight VM with NEWROOT as the rootfs.
//! Payload I/O goes to the controlling terminal (auto-detected).
//!
//! Build with `--features native` (default) for static linking,
//! or `--features cdylib` to link against libkrun.so via FFI.

#[cfg(feature = "native")]
use krun::{
    BalloonDevice, ConsoleDevice, FsDevice, MmioDeviceManager, Payload, RngDevice, VmmBuilder,
};
#[cfg(feature = "cdylib")]
use krun_cdylib::{
    BalloonDevice, ConsoleDevice, FsDevice, MmioDeviceManager, Payload, RngDevice, VmmBuilder,
};

use std::env;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    anyhow::ensure!(
        args.len() >= 3,
        "Usage: {} NEWROOT COMMAND [ARGS...]",
        args[0]
    );

    let new_root = &args[1];
    let guest_cmd = &args[2];
    let guest_args: Vec<&str> = args[3..].iter().map(|s| s.as_str()).collect();

    #[cfg(feature = "native")]
    {
        let log_file = std::fs::File::create("/tmp/krun.log")?;
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Trace)
            .target(env_logger::Target::Pipe(Box::new(std::io::BufWriter::new(
                log_file,
            ))))
            .format_timestamp_micros()
            .init();
    }

    let mut rootfs = FsDevice::new("/dev/root", new_root).map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Build init config (init-blob crate -- works in both native and cdylib mode).
    let mut full_args: Vec<&str> = vec![guest_cmd];
    full_args.extend_from_slice(&guest_args);
    let config = init_blob::Config::builder()
        .args(&full_args)
        .env(&["HOME=/root", "TERM=xterm-256color"])
        .workdir("/")
        .build();

    // Load kernel.
    let mut kernel = Payload::load_krunfw().map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Inject init files into rootfs and apply cmdline.
    // TODO: Replace with apply_init_config() once cross-library
    // ffier export is supported.
    for gf in config.guest_files() {
        let name = std::path::Path::new(gf.path)
            .file_name()
            .expect("guest file must have a filename");
        rootfs.add_overlay_file(
            name.to_str().expect("non-UTF8 guest file name"),
            &gf.data,
            gf.mode,
            gf.one_shot,
        );
    }
    kernel.append_cmdline(config.kernel_cmdline());

    // Console: default ports (hvc0 + stdin/stdout/stderr redirects).
    let mut console_builder = ConsoleDevice::builder();
    // TODO: Remove cfg once ffier-gen-rust-client maps RawFd correctly.
    #[cfg(feature = "native")]
    console_builder
        .add_default_console(libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    #[cfg(feature = "cdylib")]
    unsafe {
        use std::os::fd::BorrowedFd;
        console_builder
            .add_default_console(
                Some(BorrowedFd::borrow_raw(libc::STDIN_FILENO)),
                Some(BorrowedFd::borrow_raw(libc::STDOUT_FILENO)),
                Some(BorrowedFd::borrow_raw(libc::STDERR_FILENO)),
            )
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    }
    let console = console_builder
        .build()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let balloon = BalloonDevice::new().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let rng = RngDevice::new().map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let mut devices = MmioDeviceManager::new();
    devices.add(rootfs);
    devices.add(console);
    devices.add(balloon);
    devices.add(rng);

    let mut vmm = VmmBuilder::new()
        .vcpus(2)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .ram_mib(512)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .kernel(kernel)
        .devices(devices)
        .build()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    vmm.run();
    Ok(())
}

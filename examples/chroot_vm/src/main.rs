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
    BalloonDevice, ConsoleDevice, FsDevice, Init, MmioDeviceManager, RngDevice, VmmBuilder,
};
#[cfg(feature = "cdylib")]
use krun_cdylib::{
    BalloonDevice, ConsoleDevice, FsDevice, Init, MmioDeviceManager, RngDevice, VmmBuilder,
};

use anyhow::{Context, Result};
use std::env;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    anyhow::ensure!(
        args.len() >= 3,
        "Usage: {} NEWROOT COMMAND [ARGS...]",
        args[0]
    );

    let new_root = &args[1];
    let guest_cmd = &args[2];
    let guest_args: Vec<&str> = args[3..].iter().map(|s| s.as_str()).collect();

    // Native: init logging via env_logger directly
    // Cdylib: logging is initialized via krun_init_log() on the C side
    #[cfg(feature = "native")]
    {
        let log_file = std::fs::File::create("/tmp/krun.log").context("create log file")?;
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Trace)
            .target(env_logger::Target::Pipe(Box::new(std::io::BufWriter::new(
                log_file,
            ))))
            .format_timestamp_micros()
            .init();
    }

    let rootfs = FsDevice::new("/dev/root", new_root).context("create rootfs")?;

    let mut console_builder = ConsoleDevice::builder();
    let payload = Init::builder(&rootfs, &mut console_builder)
        .exec(guest_cmd, &guest_args)
        .context("exec")?
        .workdir("/")
        .context("workdir")?
        .env(&["HOME=/root", "TERM=xterm-256color"])
        .context("env")?
        .build()
        .context("build payload")?;
    let console = console_builder.build().context("build console")?;

    let balloon = BalloonDevice::new().context("create balloon")?;
    let rng = RngDevice::new().context("create rng")?;

    let mut devices = MmioDeviceManager::new();
    devices.add(rootfs);
    devices.add(console);
    devices.add(balloon);
    devices.add(rng);

    let mut vmm = VmmBuilder::new()
        .vcpus(2)
        .context("vcpus")?
        .ram_mib(512)
        .context("ram")?
        .payload(payload)
        .devices(devices)
        .build()
        .context("build vmm")?;
    vmm.run();
    Ok(())
}

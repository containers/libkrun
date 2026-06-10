//! Common utilities used by multiple tests

use anyhow::Context;
use std::fs;
use std::fs::create_dir;
use std::path::{Path, PathBuf};

#[cfg(feature = "native")]
use krun::{BalloonDevice, ConsoleDevice, FsDevice, InitConfig, MmioDeviceManager, RngDevice};
// TODO: cdylib support
// #[cfg(feature = "cdylib")]
// use krun_cdylib::{ ... };

use crate::TestSetup;

fn copy_guest_agent(dir: &Path) -> anyhow::Result<()> {
    let path = std::env::var_os("KRUN_TEST_GUEST_AGENT_PATH")
        .context("KRUN_TEST_GUEST_AGENT_PATH env variable not set")?;

    let output_path = dir.join("guest-agent");
    fs::copy(path, output_path).context("Failed to copy executable into vm")?;
    Ok(())
}

/// Creates the root filesystem directory and copies the guest agent into it.
/// Returns the path to the root directory. Use this when you need to configure the root
/// filesystem yourself rather than using the default `setup_and_run`.
pub fn setup_rootfs(test_setup: &TestSetup) -> anyhow::Result<PathBuf> {
    let root_dir = test_setup.tmp_dir.join("rootfs");
    if !root_dir.exists() {
        create_dir(&root_dir).context("Failed to create rootfs directory")?;
    }
    copy_guest_agent(&root_dir)?;
    Ok(root_dir)
}

/// VM configuration for a test. Tests can customize vcpus, ram, and add
/// extra devices before building.
pub struct VmConfig<'a> {
    pub vcpus: u8,
    pub ram_mib: u32,
    pub devices: MmioDeviceManager<'a>,
    kernel: krun::Payload,
}

impl<'a> VmConfig<'a> {
    /// Create a default VM config with the given vcpus and ram.
    /// Includes rootfs, console, balloon, and rng devices.
    pub fn new(vcpus: u8, ram_mib: u32, test_setup: &TestSetup) -> anyhow::Result<Self> {
        Self::new_with_init(vcpus, ram_mib, test_setup, |b| b)
    }

    /// Like [`new`](Self::new), but allows customizing the init config
    /// builder (e.g. to enable DHCP).
    pub fn new_with_init(
        vcpus: u8,
        ram_mib: u32,
        test_setup: &TestSetup,
        configure_init: impl FnOnce(krun::InitConfigBuilder) -> krun::InitConfigBuilder,
    ) -> anyhow::Result<Self> {
        krun::init_log(
            krun::LogTarget::Stderr,
            krun::LogLevel::Trace,
            krun::LogStyle::Auto,
        );

        let root_dir = test_setup.tmp_dir.join("root");
        create_dir(&root_dir).context("Failed to create root directory")?;
        copy_guest_agent(&root_dir)?;

        let mut rootfs = FsDevice::new("/dev/root", root_dir.to_str().context("non-UTF8 path")?)
            .context("create rootfs")?;

        let builder = InitConfig::builder()
            .args(&["/guest-agent", &test_setup.test_case])
            .workdir("/");
        let config = configure_init(builder).build();
        let mut kernel = krun::Payload::load_krunfw().map_err(|e| anyhow::anyhow!("{e}"))?;
        krun::apply_init_config(&config, &mut rootfs, &mut kernel);

        let mut console_builder = ConsoleDevice::builder();
        console_builder.add_console_port("", krun::port_io::output_to_log(log::Level::Info));
        console_builder
            .add_io_port("krun-stdin", Some(libc::STDIN_FILENO), None)
            .context("add stdin port")?;
        console_builder
            .add_io_port("krun-stdout", None, Some(libc::STDOUT_FILENO))
            .context("add stdout port")?;
        console_builder
            .add_io_port("krun-stderr", None, Some(libc::STDERR_FILENO))
            .context("add stderr port")?;
        let console = console_builder.build().context("build console")?;

        let mut devices = MmioDeviceManager::new();
        devices.add(BalloonDevice::new().context("balloon")?);
        devices.add(RngDevice::new().context("rng")?);
        devices.add(console);
        devices.add(rootfs);

        Ok(VmConfig {
            vcpus,
            ram_mib,
            devices,
            kernel,
        })
    }

    /// Build and run the VM. This call does not return.
    pub fn build_and_run(self) -> anyhow::Result<()> {
        let mut vmm = krun::VmmBuilder::new()
            .vcpus(self.vcpus)
            .context("vcpus")?
            .ram_mib(self.ram_mib)
            .context("ram")?
            .kernel(self.kernel)
            .devices(self.devices)
            .build()
            .context("build vmm")?;
        vmm.run();
        Ok(())
    }
}

/// Common shortcut: set up a VM with defaults and run the guest agent.
/// This is the v2 equivalent of the old `setup_fs_and_enter`.
pub fn setup_and_run(vcpus: u8, ram_mib: u32, test_setup: TestSetup) -> anyhow::Result<()> {
    let vm_config = VmConfig::new(vcpus, ram_mib, &test_setup)?;
    vm_config.build_and_run()
}

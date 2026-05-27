//! Common utilities used by multiple tests

use anyhow::Context;
use std::fs;
use std::fs::create_dir;
use std::path::{Path, PathBuf};

#[cfg(feature = "native")]
use krun::{
    BalloonDevice, ConsoleDevice, FsDevice, Init, MmioDeviceManager, RngDevice, VmmBuilder,
};
#[cfg(feature = "cdylib")]
use krun_cdylib::{
    BalloonDevice, ConsoleDevice, FsDevice, Init, MmioDeviceManager, RngDevice, VmmBuilder,
};

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
}

impl<'a> VmConfig<'a> {
    /// Create a default VM config with the given vcpus and ram.
    /// Includes rootfs, console, balloon, and rng devices.
    pub fn new(vcpus: u8, ram_mib: u32, test_setup: &TestSetup) -> anyhow::Result<(Self, Init)> {
        let root_dir = test_setup.tmp_dir.join("root");
        create_dir(&root_dir).context("Failed to create root directory")?;
        copy_guest_agent(&root_dir)?;

        let rootfs = FsDevice::new("/dev/root", root_dir.to_str().context("non-UTF8 path")?)
            .context("create rootfs")?;

        let mut console_builder = ConsoleDevice::builder();
        let payload = Init::builder(&rootfs, &mut console_builder)
            .exec("/guest-agent", &[&test_setup.test_case])
            .context("exec")?
            .workdir("/")
            .context("workdir")?
            .build()
            .context("build payload")?;
        let console = console_builder.build().context("build console")?;

        let mut devices = MmioDeviceManager::new();
        devices.add(rootfs);
        devices.add(console);
        devices.add(BalloonDevice::new().context("balloon")?);
        devices.add(RngDevice::new().context("rng")?);

        Ok((
            VmConfig {
                vcpus,
                ram_mib,
                devices,
            },
            payload,
        ))
    }

    /// Build and run the VM. This call does not return.
    pub fn build_and_run(self, payload: Init) -> anyhow::Result<()> {
        let mut vmm = VmmBuilder::new()
            .vcpus(self.vcpus)
            .context("vcpus")?
            .ram_mib(self.ram_mib)
            .context("ram")?
            .payload(payload)
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
    let (vm_config, payload) = VmConfig::new(vcpus, ram_mib, &test_setup)?;
    vm_config.build_and_run(payload)
}

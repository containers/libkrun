// Test that krun_set_root_disk_remount works with NullFs.
//
// Creates a tiny ext4 disk image containing only the guest-agent binary,
// boots from it via krun_set_root_disk_remount (which uses NullFs for the
// initial virtiofs root with init.krun overlaid), and verifies the guest
// successfully pivoted to the block device root.

use macros::{guest, host};

pub struct TestRootDiskRemount;

#[host]
mod host {
    use super::*;

    use crate::{ShouldRun, Test, TestSetup};
    use anyhow::Context;
    use std::process::Command;

    use krun::{
        BalloonDevice, BlockDevice, ConsoleDevice, FsDevice, InitConfig, MmioDeviceManager,
        RngDevice, VmmBuilder,
    };

    fn create_disk_image(guest_agent_path: &str, output_path: &str) {
        let staging = format!("{output_path}.staging");
        std::fs::create_dir_all(&staging).expect("mkdir staging");
        std::fs::copy(guest_agent_path, format!("{staging}/guest-agent"))
            .expect("copy guest-agent");
        std::fs::write(
            format!("{staging}/block-marker"),
            "booted-from-block-device",
        )
        .expect("write marker");

        let status = Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-d", &staging, output_path, "32M"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("mke2fs failed");
        assert!(status.success(), "mke2fs failed");
        std::fs::remove_dir_all(&staging).expect("cleanup staging");
    }

    impl Test for TestRootDiskRemount {
        fn should_run(&self) -> ShouldRun {
            if !cfg!(feature = "blk") {
                return ShouldRun::No("libkrun compiled without BLK");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let guest_agent_path = std::env::var("KRUN_TEST_GUEST_AGENT_PATH")
                .expect("KRUN_TEST_GUEST_AGENT_PATH not set");

            let disk_path = format!("{}/rootfs.ext4", test_setup.tmp_dir.display());
            create_disk_image(&guest_agent_path, &disk_path);

            // NullFs root — init will pivot to the block device.
            let mut rootfs = FsDevice::new_null("/dev/root").context("create null rootfs")?;

            // Virtual dirs needed by init before pivot.
            for dir in ["dev", "proc", "sys", "newroot"] {
                rootfs.add_overlay_dir(dir, 0o755);
            }

            let config = InitConfig::builder()
                .args(&["/guest-agent", &test_setup.test_case])
                .workdir("/")
                .block_root("/dev/vda", Some("ext4"), None)
                .build();
            let mut kernel = krun::Payload::load_krunfw().context("load krunfw")?;
            krun::apply_init_config(&config, &mut rootfs, &mut kernel);

            let mut console_builder = ConsoleDevice::builder();
            console_builder
                .add_io_port("", None, Some(libc::STDERR_FILENO))
                .context("add default console port")?;
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

            let block = BlockDevice::new("vda", &disk_path, false).context("create block")?;

            let mut devices = MmioDeviceManager::new();
            devices.add(rootfs);
            devices.add(console);
            devices.add(block);
            devices.add(BalloonDevice::new().context("balloon")?);
            devices.add(RngDevice::new().context("rng")?);

            let mut vmm = VmmBuilder::new()
                .vcpus(1)
                .context("vcpus")?
                .ram_mib(512)
                .context("ram")?
                .kernel(kernel)
                .devices(devices)
                .build()
                .context("build vmm")?;
            vmm.run();
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::fs;
    use std::path::Path;

    impl Test for TestRootDiskRemount {
        fn in_guest(self: Box<Self>) {
            // Verify we're running from the block device root.
            let marker = fs::read_to_string("/block-marker")
                .expect("Failed to read /block-marker — not on block device root?");
            assert_eq!(marker, "booted-from-block-device");

            // The init.krun virtual file should be gone (one-shot, and we
            // pivoted away from the NullFs root anyway).
            assert!(!Path::new("/init.krun").exists());

            // /proc and /dev should be mounted (init re-mounts after pivot).
            assert!(Path::new("/proc/self").exists(), "/proc/self missing");
            assert!(Path::new("/dev/null").exists(), "/dev/null missing");

            println!("OK");
        }
    }
}

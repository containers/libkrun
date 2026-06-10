// Test the AugmentFs overlay over a NullFs.
//
// Boots a VM with NO host filesystem — the root virtiofs is backed entirely
// by virtual inodes: init.krun (one-shot), the guest-agent binary (one-shot),
// a .krun_config.json (one-shot), persistent test files, and virtual
// directories as mount points for /dev, /proc, /sys.

use macros::{guest, host};

pub struct TestAugmentFs;

fn make_test_payload() -> Vec<u8> {
    (0..8192u32).map(|i| (i % 251) as u8).collect()
}

#[host]
mod host {
    use super::*;

    use crate::{Test, TestSetup};
    use anyhow::Context;

    use krun::{
        BalloonDevice, ConsoleDevice, FsDevice, InitConfig, MmioDeviceManager, RngDevice,
        VmmBuilder,
    };

    impl Test for TestAugmentFs {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // Read the guest-agent binary into memory.
            let guest_agent_path = std::env::var("KRUN_TEST_GUEST_AGENT_PATH")
                .expect("KRUN_TEST_GUEST_AGENT_PATH not set");
            let guest_agent_bytes =
                std::fs::read(&guest_agent_path).expect("Failed to read guest-agent");

            // Set up root with NO host directory (NullFs).
            let mut rootfs = FsDevice::new_null("/dev/root").context("create null rootfs")?;

            // Virtual directories needed by init as mount points.
            for dir in ["dev", "proc", "sys"] {
                rootfs.add_overlay_dir(dir, 0o040_755);
            }

            // Build init config via OCI JSON and inject into rootfs.
            let json = format!(
                r#"{{"process": {{"args": ["/guest-agent", "{}"], "cwd": "/"}}}}"#,
                test_setup.test_case,
            );
            let config = InitConfig::from_oci_config_json(&json).context("parse OCI config")?;
            let mut kernel = krun::Payload::load_krunfw().context("load krunfw")?;
            krun::apply_init_config(&config, &mut rootfs, &mut kernel);

            // Overlay guest-agent (one-shot, executable).
            rootfs.add_overlay_file("guest-agent", &guest_agent_bytes, 0o100_755, true);

            // Overlay a persistent marker file.
            rootfs.add_overlay_file(
                "marker.txt",
                b"virtual-file-marker-content-12345",
                0o100_644,
                false,
            );

            // Overlay a deterministic 8 KiB payload for range-read tests.
            rootfs.add_overlay_file("testdata.bin", &make_test_payload(), 0o100_444, false);

            // Nested path test: etc/ -> etc/nested/ -> etc/nested/deep.txt
            rootfs.add_overlay_dir("etc", 0o040_755);
            rootfs.add_overlay_dir("etc/nested", 0o040_755);
            rootfs.add_overlay_file(
                "etc/nested/deep.txt",
                b"deep-nested-content",
                0o100_644,
                false,
            );

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
            devices.add(rootfs);
            devices.add(console);
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
    use std::io::{ErrorKind, Read, Seek, SeekFrom};
    use std::path::Path;

    impl Test for TestAugmentFs {
        fn in_guest(self: Box<Self>) {
            // --- One-shot files should be gone ---
            assert!(
                !Path::new("/.krun_config.json").exists(),
                ".krun_config.json should be gone (one-shot)"
            );
            assert!(
                !Path::new("/init.krun").exists(),
                "init.krun should be gone (one-shot)"
            );

            // --- One-shot guest-agent can't see itself ---
            assert!(
                !Path::new("/guest-agent").exists(),
                "guest-agent should be gone (one-shot)"
            );

            // --- Virtual directories should be accessible ---
            // init already mounted over these, but let's verify they
            // exist as directories (the mount points came from our
            // virtual dir overlay).
            for dir in ["/dev", "/proc", "/sys"] {
                let meta = fs::metadata(dir).unwrap_or_else(|e| panic!("{dir} should exist: {e}"));
                assert!(meta.is_dir(), "{dir} should be a directory");
            }

            // Verify the mounts actually worked by checking known entries.
            assert!(
                Path::new("/dev/null").exists(),
                "/dev/null should exist (devtmpfs)"
            );
            assert!(
                Path::new("/proc/self").exists(),
                "/proc/self should exist (procfs)"
            );
            assert!(
                Path::new("/sys/kernel").exists(),
                "/sys/kernel should exist (sysfs)"
            );

            // Verify directory listing works on each mounted fs.
            let dev_entries: Vec<_> = fs::read_dir("/dev").expect("read_dir /dev").collect();
            assert!(!dev_entries.is_empty(), "/dev listing should not be empty");

            let proc_entries: Vec<_> = fs::read_dir("/proc").expect("read_dir /proc").collect();
            assert!(
                !proc_entries.is_empty(),
                "/proc listing should not be empty"
            );

            let sys_entries: Vec<_> = fs::read_dir("/sys").expect("read_dir /sys").collect();
            assert!(!sys_entries.is_empty(), "/sys listing should not be empty");

            // --- Persistent files should still exist ---
            assert!(Path::new("/marker.txt").exists(), "marker.txt should exist");
            assert!(
                Path::new("/testdata.bin").exists(),
                "testdata.bin should exist"
            );

            // --- Read + verify marker content ---
            let content = fs::read_to_string("/marker.txt").expect("read marker.txt");
            assert_eq!(content, "virtual-file-marker-content-12345");

            // --- Repeated reads return the same data ---
            let content2 = fs::read_to_string("/marker.txt").expect("re-read marker.txt");
            assert_eq!(content, content2, "repeated reads differ");

            // --- Write should fail ---
            let err = fs::OpenOptions::new()
                .write(true)
                .open("/marker.txt")
                .expect_err("write-open should fail");
            assert_eq!(err.kind(), ErrorKind::PermissionDenied);

            // --- stat reports correct size ---
            let meta = fs::metadata("/testdata.bin").expect("stat testdata.bin");
            assert_eq!(meta.len(), 8192, "testdata.bin size mismatch");

            // --- Range reads on the 8 KiB payload ---
            let expected = make_test_payload();
            let mut f = fs::File::open("/testdata.bin").expect("open testdata.bin");

            // Full read.
            let got = fs::read("/testdata.bin").expect("full read");
            assert_eq!(got, expected, "full read mismatch");

            // Read first 256 bytes.
            let mut buf = vec![0u8; 256];
            f.read_exact(&mut buf).expect("read first 256");
            assert_eq!(buf, &expected[..256], "first 256 bytes mismatch");

            // Seek to offset 4000, read 512 bytes.
            f.seek(SeekFrom::Start(4000)).expect("seek to 4000");
            let mut buf = vec![0u8; 512];
            f.read_exact(&mut buf).expect("read at offset 4000");
            assert_eq!(buf, &expected[4000..4512], "range [4000..4512] mismatch");

            // Seek to last 10 bytes.
            f.seek(SeekFrom::End(-10)).expect("seek to end-10");
            let mut buf = vec![0u8; 10];
            f.read_exact(&mut buf).expect("read last 10");
            assert_eq!(buf, &expected[8182..8192], "last 10 bytes mismatch");

            // Read past EOF should return 0 bytes.
            f.seek(SeekFrom::Start(8192)).expect("seek to EOF");
            let mut buf = vec![0u8; 100];
            let n = f.read(&mut buf).expect("read past EOF");
            assert_eq!(n, 0, "read past EOF should return 0");

            // Seek back to start, re-read, verify consistency.
            f.seek(SeekFrom::Start(0)).expect("seek to start");
            let mut full = Vec::new();
            f.read_to_end(&mut full).expect("read_to_end");
            assert_eq!(full, expected, "read_to_end mismatch");

            // --- Nested path test (2-level: etc/nested/deep.txt) ---
            let deep =
                fs::read_to_string("/etc/nested/deep.txt").expect("read /etc/nested/deep.txt");
            assert_eq!(deep, "deep-nested-content");

            println!("OK");
        }
    }
}

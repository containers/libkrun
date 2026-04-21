use macros::{guest, host};

pub struct TestVirtioFsMisc;

#[host]
mod host {
    use super::*;

    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestOutcome, TestSetup};
    use krun_sys::*;
    use std::io::Read;

    impl Test for TestVirtioFsMisc {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 1024))?;
                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, test_setup: TestSetup) -> TestOutcome {
            let output = String::from_utf8(stdout).unwrap();
            if output != "OK\n" {
                return TestOutcome::Fail(format!(
                    "expected exactly {:?}, got {:?}",
                    "OK\n", output
                ));
            }

            let root = test_setup.tmp_dir.join("rootfs");

            // Verify fallocate basic: file should be at least 4096 bytes
            let meta = std::fs::metadata(root.join("test_fallocate_basic")).unwrap();
            assert!(
                meta.len() >= 4096,
                "host: file size after allocate: {} (expected >= 4096)",
                meta.len()
            );

            // Verify punch hole: read the file and check the hole is zeroed
            let mut f = std::fs::File::open(root.join("test_fallocate_punch_hole")).unwrap();
            let mut contents = Vec::new();
            f.read_to_end(&mut contents).unwrap();

            assert_eq!(contents.len(), 16384, "host: punch hole file should be 16K");
            assert!(
                contents[..4096].iter().all(|&b| b == 0xAA),
                "host: data before hole should be 0xAA"
            );
            assert!(
                contents[4096..8192].iter().all(|&b| b == 0),
                "host: punched hole region should be zeroed"
            );
            assert!(
                contents[8192..].iter().all(|&b| b == 0xAA),
                "host: data after hole should be 0xAA"
            );

            TestOutcome::Pass
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

    use nix::fcntl::{fallocate, FallocateFlags};

    fn test_fallocate_basic() {
        let path = "/test_fallocate_basic";
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();

        fallocate(f.as_raw_fd(), FallocateFlags::empty(), 0, 4096)
            .expect("fallocate(ALLOCATE_RANGE) failed");

        let meta = f.metadata().unwrap();
        assert!(
            meta.len() >= 4096,
            "file size after allocate: {} (expected >= 4096)",
            meta.len()
        );
    }

    fn test_fallocate_keep_size() {
        let path = "/test_fallocate_keep_size";
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();

        fallocate(f.as_raw_fd(), FallocateFlags::FALLOC_FL_KEEP_SIZE, 0, 65536)
            .expect("fallocate(KEEP_SIZE) failed");

        let meta = f.metadata().unwrap();
        assert_eq!(meta.len(), 0, "file size should remain 0 with KEEP_SIZE");
        assert!(
            meta.blocks() > 0,
            "blocks should be allocated with KEEP_SIZE"
        );
    }

    fn test_fallocate_punch_hole() {
        let path = "/test_fallocate_punch_hole";
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();

        // Write 16K of non-zero data
        let data = vec![0xAAu8; 16384];
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();

        let size_before = f.metadata().unwrap().len();

        // Punch a 4K hole in the middle (offset 4096, length 4096)
        fallocate(
            f.as_raw_fd(),
            FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE,
            4096,
            4096,
        )
        .expect("fallocate(PUNCH_HOLE) failed");

        let meta = f.metadata().unwrap();
        assert_eq!(
            meta.len(),
            size_before,
            "file size should not change after PUNCH_HOLE"
        );

        // Verify the hole is zeroed
        f.seek(SeekFrom::Start(4096)).unwrap();
        let mut hole_data = vec![0u8; 4096];
        f.read_exact(&mut hole_data).unwrap();
        assert!(
            hole_data.iter().all(|&b| b == 0),
            "punched region should be zeroed"
        );

        // Verify data around the hole is intact
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut before_hole = vec![0u8; 4096];
        f.read_exact(&mut before_hole).unwrap();
        assert!(
            before_hole.iter().all(|&b| b == 0xAA),
            "data before hole should be intact"
        );

        f.seek(SeekFrom::Start(8192)).unwrap();
        let mut after_hole = vec![0u8; 4096];
        f.read_exact(&mut after_hole).unwrap();
        assert!(
            after_hole.iter().all(|&b| b == 0xAA),
            "data after hole should be intact"
        );
    }

    fn test_fallocate_punch_hole_requires_keep_size() {
        let path = "/test_fallocate_punch_no_keepsize";
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();

        let ret = fallocate(f.as_raw_fd(), FallocateFlags::FALLOC_FL_PUNCH_HOLE, 0, 4096);
        assert!(ret.is_err(), "PUNCH_HOLE without KEEP_SIZE should fail");
    }

    impl Test for TestVirtioFsMisc {
        fn in_guest(self: Box<Self>) {
            test_fallocate_basic();
            test_fallocate_keep_size();
            test_fallocate_punch_hole();
            test_fallocate_punch_hole_requires_keep_size();

            println!("OK");
        }
    }
}

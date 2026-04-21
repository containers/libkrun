use macros::{guest, host};

pub struct TestPjdfstest;

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter_with_env;
    use crate::{krun_call, krun_call_u32, ShouldRun, Test, TestOutcome, TestSetup};
    use krun_sys::*;
    use std::ffi::CString;

    const CONTAINERFILE: &str = "\
FROM fedora:43
RUN dnf install -y autoconf automake gcc make perl-Test-Harness git openssl && dnf clean all
RUN git init /pjdfstest \
 && git -C /pjdfstest fetch --depth 1 https://github.com/mtjhrc/pjdfstest.git 13056ef8862b2d8dab07c59531ffea0427d1ea2b \
 && git -C /pjdfstest checkout FETCH_HEAD
WORKDIR /pjdfstest
RUN autoreconf -ifs && ./configure && make pjdfstest
";

    impl Test for TestPjdfstest {
        fn should_run(&self) -> ShouldRun {
            if option_env!("PJDFSTEST").is_none() {
                return ShouldRun::No("PJDFSTEST not set");
            }
            ShouldRun::Yes
        }

        fn rootfs_image(&self) -> Option<&'static str> {
            Some(CONTAINERFILE)
        }

        fn timeout_secs(&self) -> u64 {
            600
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let host_os = if cfg!(target_os = "macos") {
                "Darwin"
            } else {
                "Linux"
            };
            let host_os_env = CString::new(format!("PJDFSTEST_HOST_OS={host_os}"))?;
            unsafe {
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 2, 1024))?;
                setup_fs_and_enter_with_env(ctx, test_setup, &[host_os_env.as_c_str()])?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let stdout = String::from_utf8_lossy(&stdout);

            if stdout.contains("Result: PASS") {
                TestOutcome::Pass
            } else if stdout.contains("Result: FAIL") || stdout.contains("Result: NOTESTS") {
                TestOutcome::Fail(stdout.to_string())
            } else if stdout.trim() == "OK" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(stdout.to_string())
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::process::Command;

    impl Test for TestPjdfstest {
        fn in_guest(self: Box<Self>) {
            // Create a test directory on the filesystem under test
            std::fs::create_dir_all("/tmp/pjdfstest-work").expect("Failed to create test dir");

            let status = Command::new("/usr/bin/prove")
                .arg("-rv")
                .arg("/pjdfstest/tests")
                .current_dir("/tmp/pjdfstest-work")
                .status()
                .expect("Failed to run prove");

            if !status.success() {
                panic!("prove exited with status: {}", status.code().unwrap_or(-1));
            }
        }
    }
}

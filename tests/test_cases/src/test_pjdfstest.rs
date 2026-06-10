use macros::{guest, host};

pub struct TestPjdfstest;

#[host]
mod host {
    use super::*;

    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    use anyhow::Context;
    use krun::{
        BalloonDevice, ConsoleDevice, FsDevice, InitConfig, MmioDeviceManager, RngDevice,
        VmmBuilder,
    };

    use macros::env_or_default;

    // Set PJDFSTEST_REPO and PJDFSTEST_COMMIT at build time to enable this test.
    const CONTAINERFILE: &str = concat!(
        "FROM fedora:43\n",
        "RUN dnf install -y autoconf automake gcc make perl-Test-Harness git openssl && dnf clean all\n",
        "RUN git init /pjdfstest \\\n",
        " && git -C /pjdfstest fetch --depth 1 ",
        env_or_default!("PJDFSTEST_REPO", ""),
        " ",
        env_or_default!("PJDFSTEST_COMMIT", ""),
        " \\\n",
        " && git -C /pjdfstest checkout FETCH_HEAD\n",
        "WORKDIR /pjdfstest\n",
        "RUN autoreconf -ifs && ./configure && make pjdfstest\n",
    );

    impl Test for TestPjdfstest {
        fn should_run(&self) -> ShouldRun {
            if option_env!("PJDFSTEST_REPO").is_none() || option_env!("PJDFSTEST_COMMIT").is_none()
            {
                return ShouldRun::No("PJDFSTEST_REPO/PJDFSTEST_COMMIT not set");
            }
            ShouldRun::Yes
        }

        fn rootfs_image(&self) -> Option<&'static str> {
            Some(CONTAINERFILE)
        }

        fn timeout_secs(&self) -> u64 {
            1800
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let host_os = if cfg!(target_os = "macos") {
                "Darwin"
            } else {
                "Linux"
            };
            let host_os_env = format!("PJDFSTEST_HOST_OS={host_os}");

            let root_dir = test_setup.tmp_dir.join("root");
            std::fs::create_dir(&root_dir).context("Failed to create root directory")?;
            let agent_src = std::env::var_os("KRUN_TEST_GUEST_AGENT_PATH")
                .context("KRUN_TEST_GUEST_AGENT_PATH not set")?;
            std::fs::copy(agent_src, root_dir.join("guest-agent")).context("copy guest-agent")?;

            let mut rootfs =
                FsDevice::new("/dev/root", root_dir.to_str().context("non-UTF8 path")?)
                    .context("create rootfs")?;

            let config = InitConfig::builder()
                .args(&["/guest-agent", &test_setup.test_case])
                .env(&[&host_os_env])
                .workdir("/")
                .build();
            let mut kernel = krun::Payload::load_krunfw().expect("load krunfw");
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

            let mut devices = MmioDeviceManager::new();
            devices.add(rootfs);
            devices.add(console);
            devices.add(BalloonDevice::new().context("balloon")?);
            devices.add(RngDevice::new().context("rng")?);

            let mut vmm = VmmBuilder::new()
                .vcpus(2)
                .context("vcpus")?
                .ram_mib(1024)
                .context("ram")?
                .kernel(kernel)
                .devices(devices)
                .build()
                .context("build vmm")?;
            vmm.run();
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

//! iperf3-based performance tests for virtio-net backends
//!
//! Each test:
//! 1. Host: Start iperf3 server + network backend
//! 2. Guest: Configure eth0, run iperf3 client
//! 3. Host: Parse iperf3 JSON output, produce markdown report
//!
//! Tests are parametrized by backend and direction (upload vs download).

use macros::{guest, host};

#[host]
use crate::{ShouldRun, TestSetup};

/// Virtio-net performance test with configurable backend and direction
pub struct TestNetPerf {
    #[cfg(feature = "guest")]
    guest_ip: [u8; 4],
    #[cfg(feature = "guest")]
    host_ip: [u8; 4],
    #[cfg(feature = "guest")]
    netmask: [u8; 4],
    port: u16,
    /// If true, run iperf3 with -R (reverse: server sends, client receives = download)
    reverse: bool,
    #[cfg(feature = "host")]
    should_run: fn() -> ShouldRun,
    #[cfg(feature = "host")]
    setup_backend: fn(u32, &TestSetup) -> anyhow::Result<()>,
    #[cfg(feature = "host")]
    cleanup: Option<fn()>,
}

impl TestNetPerf {
    pub fn new_passt_upload() -> Self {
        Self {
            #[cfg(feature = "guest")]
            guest_ip: [169, 254, 2, 1],
            #[cfg(feature = "guest")]
            host_ip: [169, 254, 2, 2],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 0, 0],
            port: 15100,
            reverse: false,
            #[cfg(feature = "host")]
            should_run: crate::test_net::passt::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::passt::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_passt_download() -> Self {
        Self {
            #[cfg(feature = "guest")]
            guest_ip: [169, 254, 2, 1],
            #[cfg(feature = "guest")]
            host_ip: [169, 254, 2, 2],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 0, 0],
            port: 15110,
            reverse: true,
            #[cfg(feature = "host")]
            should_run: crate::test_net::passt::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::passt::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_tap_upload() -> Self {
        Self {
            #[cfg(feature = "guest")]
            guest_ip: [10, 0, 0, 2],
            #[cfg(feature = "guest")]
            host_ip: [10, 0, 0, 1],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 255, 0],
            port: 15101,
            reverse: false,
            #[cfg(feature = "host")]
            should_run: crate::test_net::tap::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::tap::setup_backend,
            #[cfg(feature = "host")]
            cleanup: Some(crate::test_net::tap::cleanup),
        }
    }

    pub fn new_tap_download() -> Self {
        Self {
            #[cfg(feature = "guest")]
            guest_ip: [10, 0, 0, 2],
            #[cfg(feature = "guest")]
            host_ip: [10, 0, 0, 1],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 255, 0],
            port: 15111,
            reverse: true,
            #[cfg(feature = "host")]
            should_run: crate::test_net::tap::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::tap::setup_backend,
            #[cfg(feature = "host")]
            cleanup: Some(crate::test_net::tap::cleanup),
        }
    }

    pub fn new_gvproxy_upload() -> Self {
        Self {
            #[cfg(feature = "guest")]
            guest_ip: [192, 168, 127, 2],
            #[cfg(feature = "guest")]
            host_ip: [192, 168, 127, 254],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 255, 0],
            port: 15102,
            reverse: false,
            #[cfg(feature = "host")]
            should_run: crate::test_net::gvproxy::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::gvproxy::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_gvproxy_download() -> Self {
        Self {
            #[cfg(feature = "guest")]
            guest_ip: [192, 168, 127, 2],
            #[cfg(feature = "guest")]
            host_ip: [192, 168, 127, 254],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 255, 0],
            port: 15112,
            reverse: true,
            #[cfg(feature = "host")]
            should_run: crate::test_net::gvproxy::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::gvproxy::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_vmnet_helper_upload() -> Self {
        Self {
            #[cfg(feature = "guest")]
            guest_ip: [192, 168, 105, 2],
            #[cfg(feature = "guest")]
            host_ip: [192, 168, 105, 1],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 255, 0],
            port: 15103,
            reverse: false,
            #[cfg(feature = "host")]
            should_run: crate::test_net::vmnet_helper::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::vmnet_helper::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }

    pub fn new_vmnet_helper_download() -> Self {
        Self {
            #[cfg(feature = "guest")]
            guest_ip: [192, 168, 105, 2],
            #[cfg(feature = "guest")]
            host_ip: [192, 168, 105, 1],
            #[cfg(feature = "guest")]
            netmask: [255, 255, 255, 0],
            port: 15113,
            reverse: true,
            #[cfg(feature = "host")]
            should_run: crate::test_net::vmnet_helper::should_run,
            #[cfg(feature = "host")]
            setup_backend: crate::test_net::vmnet_helper::setup_backend,
            #[cfg(feature = "host")]
            cleanup: None,
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_existing_rootfs_and_enter;
    use crate::rootfs;
    use crate::{krun_call, krun_call_u32, Test, TestOutcome, TestSetup};
    use krun_sys::*;
    use std::process::{Child, Command, Stdio};

    const ROOTFS_IMAGE: &str = "fedora-iperf3";

    fn iperf3_available() -> bool {
        Command::new("iperf3")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn start_iperf_server(port: u16) -> std::io::Result<Child> {
        Command::new("iperf3")
            .arg("-s")
            .arg("-p")
            .arg(port.to_string())
            .arg("-1") // one-off: exit after first client
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }

    #[derive(serde::Deserialize)]
    struct Iperf3Output {
        intervals: Vec<Iperf3Interval>,
        end: Iperf3End,
    }

    #[derive(serde::Deserialize)]
    struct Iperf3Interval {
        sum: Iperf3Sum,
    }

    #[derive(serde::Deserialize)]
    struct Iperf3End {
        sum_sent: Iperf3Sum,
        sum_received: Iperf3Sum,
    }

    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct Iperf3Sum {
        start: f64,
        end: f64,
        seconds: f64,
        bytes: f64,
        bits_per_second: f64,
    }

    struct Iperf3Report {
        output: Iperf3Output,
        reverse: bool,
    }

    impl Iperf3Report {
        fn label(&self) -> &'static str {
            if self.reverse {
                "Download (host->guest)"
            } else {
                "Upload (guest->host)"
            }
        }

        fn summary(&self) -> &Iperf3Sum {
            if self.reverse {
                &self.output.end.sum_received
            } else {
                &self.output.end.sum_sent
            }
        }
    }

    impl crate::ReportImpl for Iperf3Report {
        fn fmt_text(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let i = f.width().unwrap_or(0);
            writeln!(f, "{:i$}iperf3 — {}\n", "", self.label())?;
            writeln!(
                f,
                "{:i$}{:<9}  {:>18}  {:>14}",
                "", "Interval", "Throughput", "Transferred"
            )?;
            writeln!(f, "{:i$}{:-<9}  {:-<18}  {:-<14}", "", "", "", "")?;
            for interval in &self.output.intervals {
                let s = &interval.sum;
                let iv = format!("{:.0}-{:.0}s", s.start, s.end);
                writeln!(
                    f,
                    "{:i$}{:<9}  {:>11.2} Gbit/s  {:>10.2} GiB",
                    "",
                    iv,
                    s.bits_per_second / 1_000_000_000.0,
                    s.bytes / (1024.0 * 1024.0 * 1024.0),
                )?;
            }
            let s = self.summary();
            writeln!(f, "{:i$}{:-<9}  {:-<18}  {:-<14}", "", "", "", "")?;
            write!(
                f,
                "{:i$}{:<9}  {:>11.2} Gbit/s  {:>10.2} GiB",
                "",
                "Total",
                s.bits_per_second / 1_000_000_000.0,
                s.bytes / (1024.0 * 1024.0 * 1024.0),
            )
        }

        fn fmt_gh_markdown(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(f, "### iperf3 — {}\n", self.label())?;
            writeln!(f, "| Interval | Throughput | Transferred |")?;
            writeln!(f, "|----------|-----------|-------------|")?;
            for interval in &self.output.intervals {
                let s = &interval.sum;
                writeln!(
                    f,
                    "| {:.0}-{:.0}s | {:.2} Gbit/s | {:.2} GiB |",
                    s.start,
                    s.end,
                    s.bits_per_second / 1_000_000_000.0,
                    s.bytes / (1024.0 * 1024.0 * 1024.0),
                )?;
            }
            let s = self.summary();
            write!(
                f,
                "| **Total** | **{:.2} Gbit/s** | **{:.2} GiB** |",
                s.bits_per_second / 1_000_000_000.0,
                s.bytes / (1024.0 * 1024.0 * 1024.0),
            )
        }
    }

    impl Test for TestNetPerf {
        fn should_run(&self) -> ShouldRun {
            if option_env!("IPERF_DURATION").is_none() {
                return ShouldRun::No("IPERF_DURATION not set");
            }
            if unsafe { krun_call_u32!(krun_has_feature(KRUN_FEATURE_NET.into())) }.ok() != Some(1)
            {
                return ShouldRun::No("libkrun compiled without NET");
            }
            let backend_result = (self.should_run)();
            if let ShouldRun::No(_) = backend_result {
                return backend_result;
            }
            if !iperf3_available() {
                return ShouldRun::No("iperf3 not installed on host");
            }
            if !rootfs::rootfs_is_built(ROOTFS_IMAGE) {
                return ShouldRun::No("rootfs not built (run: make test)");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // Start iperf3 server on host (one-off, exits after first client)
            let mut iperf_server = start_iperf_server(self.port)?;

            // Give iperf3 server a moment to start
            std::thread::sleep(std::time::Duration::from_millis(200));

            // Check it's still running
            if let Some(status) = iperf_server.try_wait()? {
                anyhow::bail!("iperf3 server exited early: {status}");
            }

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;

                // Backend-specific setup
                (self.setup_backend)(ctx, &test_setup)?;

                let rootfs = test_setup.tmp_dir.join("rootfs");
                rootfs::extract_rootfs(ROOTFS_IMAGE, &rootfs)?;
                setup_existing_rootfs_and_enter(ctx, test_setup, &rootfs)?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, child: std::process::Child) -> TestOutcome {
            let output = child.wait_with_output().unwrap();
            if let Some(cleanup) = self.cleanup {
                cleanup();
            }
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();

            match serde_json::from_str::<Iperf3Output>(&stdout) {
                Ok(iperf_output) => TestOutcome::Report(Box::new(Iperf3Report {
                    output: iperf_output,
                    reverse: self.reverse,
                })),
                Err(_) => TestOutcome::Fail,
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::net_config::configure_interface;
    use crate::Test;
    use std::process::Command;
    use std::time::Duration;

    impl Test for TestNetPerf {
        fn in_guest(self: Box<Self>) {
            // Configure eth0 with static IP
            configure_interface("eth0", self.guest_ip, self.netmask)
                .expect("Failed to configure eth0");

            let host_ip = format!(
                "{}.{}.{}.{}",
                self.host_ip[0], self.host_ip[1], self.host_ip[2], self.host_ip[3]
            );

            // Give the network a moment to come up
            std::thread::sleep(Duration::from_secs(2));

            let Some(iperf_duration) = option_env!("IPERF_DURATION") else {
                unreachable!()
            };

            // Run iperf3 client with JSON output, retry up to 5 times
            let mut last_output = None;
            for attempt in 0..5 {
                if attempt > 0 {
                    std::thread::sleep(Duration::from_secs(2));
                }

                let mut cmd = Command::new("/usr/bin/iperf3");
                cmd.arg("-c")
                    .arg(&host_ip)
                    .arg("-p")
                    .arg(self.port.to_string())
                    .arg("-t")
                    .arg(iperf_duration)
                    .arg("-J");

                if self.reverse {
                    cmd.arg("-R");
                }

                let output = cmd.output().expect("Failed to run iperf3");

                if output.status.success() {
                    // Print JSON output to stdout (host will read it)
                    let stdout = String::from_utf8(output.stdout).expect("iperf3 output not UTF-8");
                    print!("{}", stdout);
                    return;
                }

                last_output = Some(output);
            }

            let output = last_output.unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            panic!(
                "iperf3 failed after 5 attempts (exit={}):\nstderr: {}\nstdout: {}",
                output.status, stderr, stdout
            );
        }
    }
}

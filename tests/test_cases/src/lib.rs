mod test_vm_config;
use test_vm_config::TestVmConfig;

mod test_vsock_guest_connect;
use test_vsock_guest_connect::TestVsockGuestConnect;

mod test_tsi_tcp_guest_connect;
use test_tsi_tcp_guest_connect::TestTsiTcpGuestConnect;

mod test_tsi_tcp_guest_listen;
use test_tsi_tcp_guest_listen::TestTsiTcpGuestListen;

pub(crate) mod test_net;
use test_net::TestNet;

mod test_net_perf;
use test_net_perf::TestNetPerf;

mod test_multiport_console;
use test_multiport_console::TestMultiportConsole;

pub enum ShouldRun {
    Yes,
    No(&'static str),
}

impl ShouldRun {
    /// Returns Yes unless on macOS, in which case returns No with the given reason.
    pub fn yes_unless_macos(reason: &'static str) -> Self {
        if cfg!(target_os = "macos") {
            ShouldRun::No(reason)
        } else {
            ShouldRun::Yes
        }
    }
}

pub enum TestOutcome {
    Pass,
    Fail,
    Skip(&'static str),
    Report(Box<dyn ReportImpl>),
}

pub fn test_cases() -> Vec<TestCase> {
    // Register your test here:
    vec![
        TestCase::new(
            "configure-vm-1cpu-256MiB",
            Box::new(TestVmConfig {
                num_cpus: 1,
                ram_mib: 256,
            }),
        ),
        TestCase::new(
            "configure-vm-2cpu-1GiB",
            Box::new(TestVmConfig {
                num_cpus: 2,
                ram_mib: 1024,
            }),
        ),
        TestCase::new("vsock-guest-connect", Box::new(TestVsockGuestConnect)),
        TestCase::new(
            "tsi-tcp-guest-connect",
            Box::new(TestTsiTcpGuestConnect::new()),
        ),
        TestCase::new(
            "tsi-tcp-guest-listen",
            Box::new(TestTsiTcpGuestListen::new()),
        ),
        TestCase::new("net-passt", Box::new(TestNet::new_passt())),
        TestCase::new("net-tap", Box::new(TestNet::new_tap())),
        TestCase::new("net-gvproxy", Box::new(TestNet::new_gvproxy())),
        TestCase::new("net-vmnet-helper", Box::new(TestNet::new_vmnet_helper())),
        TestCase::new("multiport-console", Box::new(TestMultiportConsole)),
        TestCase::new(
            "perf-net-passt-upload",
            Box::new(TestNetPerf::new_passt_upload()),
        ),
        TestCase::new(
            "perf-net-passt-download",
            Box::new(TestNetPerf::new_passt_download()),
        ),
        TestCase::new(
            "perf-net-tap-upload",
            Box::new(TestNetPerf::new_tap_upload()),
        ),
        TestCase::new(
            "perf-net-tap-download",
            Box::new(TestNetPerf::new_tap_download()),
        ),
        TestCase::new(
            "perf-net-gvproxy-upload",
            Box::new(TestNetPerf::new_gvproxy_upload()),
        ),
        TestCase::new(
            "perf-net-gvproxy-download",
            Box::new(TestNetPerf::new_gvproxy_download()),
        ),
        TestCase::new(
            "perf-net-vmnet-helper-upload",
            Box::new(TestNetPerf::new_vmnet_helper_upload()),
        ),
        TestCase::new(
            "perf-net-vmnet-helper-download",
            Box::new(TestNetPerf::new_vmnet_helper_download()),
        ),
    ]
}

/// Registry of container images used by tests.
/// Each entry maps a name to a Containerfile that will be built and cached via podman.
#[host]
pub fn rootfs_images() -> &'static [(&'static str, &'static str)] {
    &[(
        "fedora-iperf3",
        "\
FROM fedora:43
RUN dnf install -y iperf3 && dnf clean all
",
    )]
}

////////////////////
// Implementation details:
//////////////////

pub trait ReportImpl {
    fn fmt_text(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
    fn fmt_gh_markdown(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

pub trait Report: ReportImpl {
    fn text(&self) -> ReportText<'_, Self> {
        ReportText(self)
    }

    fn gh_markdown(&self) -> ReportGhMarkdown<'_, Self> {
        ReportGhMarkdown(self)
    }
}

impl<T: ReportImpl + ?Sized> Report for T {}

pub struct ReportText<'a, T: ReportImpl + ?Sized>(pub &'a T);

impl<T: ReportImpl + ?Sized> std::fmt::Display for ReportText<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_text(f)
    }
}

pub struct ReportGhMarkdown<'a, T: ReportImpl + ?Sized>(pub &'a T);

impl<T: ReportImpl + ?Sized> std::fmt::Display for ReportGhMarkdown<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_gh_markdown(f)
    }
}

use macros::{guest, host};
#[host]
use std::path::PathBuf;
#[host]
use std::process::Child;

#[cfg(all(feature = "guest", feature = "host"))]
compile_error!("Cannot enable both guest and host in the same binary!");

#[cfg(feature = "host")]
mod common;

#[cfg(feature = "host")]
mod krun;

#[cfg(feature = "host")]
pub mod rootfs;

#[cfg(feature = "guest")]
mod net_config;

mod tcp_tester;

#[host]
#[derive(Clone, Debug)]
pub struct TestSetup {
    pub test_case: String,
    // A tmp directory for misc. artifacts used be the test (e.g. sockets)
    pub tmp_dir: PathBuf,
}

#[host]
pub trait Test {
    /// Start the VM
    fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()>;

    /// Checks the output of the (host) process which started the VM
    fn check(self: Box<Self>, child: Child) -> TestOutcome {
        let output = child.wait_with_output().unwrap();
        if String::from_utf8(output.stdout).unwrap() == "OK\n" {
            TestOutcome::Pass
        } else {
            TestOutcome::Fail
        }
    }

    /// Check if this test should run on this platform.
    fn should_run(&self) -> ShouldRun {
        ShouldRun::Yes
    }
}

#[guest]
pub trait Test {
    /// This will be executed in the guest, you can panic! if the test failed!
    fn in_guest(self: Box<Self>) {}
}

pub struct TestCase {
    pub name: &'static str,
    pub test: Box<dyn Test>,
}

impl TestCase {
    // Your test can be parametrized, so you can add the same test multiple times constructed with
    // different parameters with and specify a different name here.
    pub fn new(name: &'static str, test: Box<dyn Test>) -> Self {
        Self { name, test }
    }

    /// Check if this test should run on this platform.
    #[host]
    pub fn should_run(&self) -> ShouldRun {
        self.test.should_run()
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_testcases_have_unique_names() {
        let test_cases = test_cases();
        let mut names: HashSet<&str> = HashSet::new();

        for test_case in test_cases {
            let name = test_case.name();
            let was_inserted = names.insert(name);
            if !was_inserted {
                panic!("test_cases() contains multiple items named `{name}`")
            }

            if name == "all" {
                panic!("test_cases() contains test named {name}, but the name is reseved")
            }
        }
    }
}

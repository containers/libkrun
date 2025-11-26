mod test_vm_config;
use test_vm_config::TestVmConfig;

mod test_vsock_guest_connect;
use test_vsock_guest_connect::TestVsockGuestConnect;

mod test_tsi_unix_dgram_setsockopt;
use test_tsi_unix_dgram_setsockopt::TestTsiUnixDgramSetsockopt;

mod test_tsi;
use test_tsi::{At::*, TestTsi, Transport::*};

const UNIX_STREAM_PATH: &str = "/tmp/test-unix-stream.sock";
const UNIX_DGRAM_SERVER: &str = "/tmp/test-unix-dgram.sock";
const UNIX_DGRAM_CLIENT: &str = "/tmp/test-unix-dgram-client.sock";

mod test_multiport_console;
use test_multiport_console::TestMultiportConsole;

pub fn test_cases() -> Vec<TestCase> {
    vec![
        // VM config tests
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
        // Vsock connecting to unix socket (non TSI)
        TestCase::new("vsock-guest-connect", Box::new(TestVsockGuestConnect)),
        // Regression test for NULL pointer deref in tsi_dgram_setsockopt
        // With unfixed kernel: guest kernel panics
        // With fixed kernel: test passes
        TestCase::new(
            "tsi-unix-dgram-setsockopt",
            Box::new(TestTsiUnixDgramSetsockopt),
        ),
        TestCase::new(
            "tsi-tcp-host-guest-ipv4",
            Box::new(TestTsi::new(
                Tcp {
                    ip: IpVersion::V4,
                    port: 8000,
                },
                Host,
                Guest,
            )),
        ),
        TestCase::new(
            "tsi-tcp-host-guest-ipv6",
            Box::new(TestTsi::new(
                Tcp {
                    ip: IpVersion::V6,
                    port: 8001,
                },
                Host,
                Guest,
            )),
        ),
        TestCase::new(
            "tsi-tcp-guest-host-ipv4",
            Box::new(TestTsi::new(
                Tcp {
                    ip: IpVersion::V4,
                    port: 8002,
                },
                Guest,
                Host,
            )),
        ),
        TestCase::new(
            "tsi-tcp-guest-host-ipv6",
            Box::new(TestTsi::new(
                Tcp {
                    ip: IpVersion::V6,
                    port: 8003,
                },
                Guest,
                Host,
            )),
        ),
        TestCase::new(
            "tsi-tcp-guest-guest-ipv4",
            Box::new(TestTsi::new(
                Tcp {
                    ip: IpVersion::V4,
                    port: 8004,
                },
                Guest,
                Guest,
            )),
        ),
        TestCase::new(
            "tsi-tcp-guest-guest-ipv6",
            Box::new(TestTsi::new(
                Tcp {
                    ip: IpVersion::V6,
                    port: 8005,
                },
                Guest,
                Guest,
            )),
        ),
        TestCase::new(
            "tsi-udp-host-guest-ipv4",
            Box::new(TestTsi::new(
                Udp {
                    ip: IpVersion::V4,
                    port: 8006,
                },
                Host,
                Guest,
            )),
        ),
        TestCase::new(
            "tsi-udp-host-guest-ipv6",
            Box::new(TestTsi::new(
                Udp {
                    ip: IpVersion::V6,
                    port: 8007,
                },
                Host,
                Guest,
            )),
        ),
        TestCase::new(
            "tsi-udp-guest-guest-ipv4",
            Box::new(TestTsi::new(
                Udp {
                    ip: IpVersion::V4,
                    port: 8008,
                },
                Guest,
                Guest,
            )),
        ),
        TestCase::new(
            "tsi-udp-guest-guest-ipv6",
            Box::new(TestTsi::new(
                Udp {
                    ip: IpVersion::V6,
                    port: 8009,
                },
                Guest,
                Guest,
            )),
        ),
        TestCase::new_with_namespace(
            "tsi-unix-stream-host-guest",
            Box::new(TestTsi::new(
                UnixStream {
                    path: UNIX_STREAM_PATH,
                },
                Host,
                Guest,
            )),
        ),
        // Unix stream: both in guest
        TestCase::new(
            "tsi-unix-stream-guest-guest",
            Box::new(TestTsi::new(
                UnixStream {
                    path: UNIX_STREAM_PATH,
                },
                Guest,
                Guest,
            )),
        ),
        // TODO: this is probably still broken on the kernel side
        // TestCase::new("tsi-unix-dgram-guest-guest", Box::new(TestTsi::new(
        //    UnixDgram { server_path: UNIX_DGRAM_SERVER, client_path: UNIX_DGRAM_CLIENT }, Guest, Guest))),

        // Unix dgram: server on host (requires namespace)
        TestCase::new_with_namespace(
            "tsi-unix-dgram-host-guest",
            Box::new(TestTsi::new(
                UnixDgram {
                    server_path: UNIX_DGRAM_SERVER,
                    client_path: UNIX_DGRAM_CLIENT,
                },
                Host,
                Guest,
            )),
        ),
        TestCase::new("multiport-console", Box::new(TestMultiportConsole)),
    ]
}

////////////////////
// Implementation details:
//////////////////
use macros::{guest, host};
#[host]
use std::path::PathBuf;
#[host]
use std::process::Child;

#[cfg(all(feature = "guest", feature = "host"))]
compile_error!("Cannot enable both guest and host in the same binary!");

#[cfg(feature = "host")]
mod common;

mod datagram_tester;
#[cfg(feature = "host")]
mod krun;
mod stream_tester;

#[host]
#[derive(Clone, Debug)]
pub struct TestSetup {
    pub test_case: String,
    // A tmp directory for misc. artifacts used be the test (e.g. sockets)
    pub tmp_dir: PathBuf,
    // If true, runner has already set up namespace with chroot - root is "/"
    pub requires_namespace: bool,
}

#[host]
pub trait Test {
    /// Start the VM
    fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()>;

    /// Checks the output of the (host) process which started the VM
    fn check(self: Box<Self>, child: Child) {
        let output = child.wait_with_output().unwrap();
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "OK\n");
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
    pub requires_namespace: bool,
}

impl TestCase {
    // Your test can be parametrized, so you can add the same test multiple times constructed with
    // different parameters with and specify a different name here.
    pub fn new(name: &'static str, test: Box<dyn Test>) -> Self {
        Self {
            name,
            test,
            requires_namespace: false,
        }
    }

    pub fn new_with_namespace(name: &'static str, test: Box<dyn Test>) -> Self {
        Self {
            name,
            test,
            requires_namespace: true,
        }
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
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

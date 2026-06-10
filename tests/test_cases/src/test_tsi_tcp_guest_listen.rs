use crate::tcp_tester::TcpTester;
use macros::{guest, host};
use std::net::Ipv4Addr;

const PORT: u16 = 8001;

pub struct TestTsiTcpGuestListen {
    tcp_tester: TcpTester,
}

impl TestTsiTcpGuestListen {
    pub fn new() -> Self {
        Self {
            tcp_tester: TcpTester::new(Ipv4Addr::LOCALHOST, PORT),
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::VmConfig;
    use crate::{Test, TestSetup};
    use krun::{TsiFlags, VsockDevice};
    use std::collections::HashMap;
    use std::thread;
    use std::time::Duration;

    impl Test for TestTsiTcpGuestListen {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(1));
                self.tcp_tester.run_client();
            });

            // Forward host PORT → guest PORT for TSI listen mode
            let mut host_port_map = HashMap::new();
            host_port_map.insert(PORT, PORT);

            let vsock = VsockDevice::new(3, Some(host_port_map), None, TsiFlags::HIJACK_INET)?;

            let mut vm_config = VmConfig::new(1, 512, &test_setup)?;
            vm_config.devices.add(vsock);
            vm_config.build_and_run()
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    impl Test for TestTsiTcpGuestListen {
        fn in_guest(self: Box<Self>) {
            let listener = self.tcp_tester.create_server_socket();
            self.tcp_tester.run_server(listener);
            println!("OK");
        }
    }
}

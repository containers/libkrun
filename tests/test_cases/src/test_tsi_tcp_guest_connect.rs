use crate::tcp_tester::TcpTester;
use macros::{guest, host};
use std::net::Ipv4Addr;

const PORT: u16 = 8000;

pub struct TestTsiTcpGuestConnect {
    tcp_tester: TcpTester,
}

impl TestTsiTcpGuestConnect {
    pub fn new() -> TestTsiTcpGuestConnect {
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
    use std::thread;

    impl Test for TestTsiTcpGuestConnect {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let listener = self.tcp_tester.create_server_socket();
            thread::spawn(move || self.tcp_tester.run_server(listener));

            let vsock = VsockDevice::new(3, None, None, TsiFlags::HIJACK_INET)?;

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

    impl Test for TestTsiTcpGuestConnect {
        fn in_guest(self: Box<Self>) {
            self.tcp_tester.run_client();
            println!("OK");
        }
    }
}

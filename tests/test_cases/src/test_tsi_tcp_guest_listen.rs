use crate::tcp_tester::TcpTester;
use macros::{guest, host};

const PORT: u16 = 8001;

pub struct TestTsiTcpGuestListen {
    tcp_tester: TcpTester,
}

impl TestTsiTcpGuestListen {
    pub fn new() -> Self {
        Self {
            tcp_tester: TcpTester::new(PORT),
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32, Test, TestSetup};
    use krun_sys::*;
    use std::ffi::CString;
    use std::ptr::null;
    use std::thread;
    use std::time::Duration;

    impl Test for TestTsiTcpGuestListen {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(1));
                    self.tcp_tester.run_client();
                });

                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                let port_mapping = format!("{PORT}:{PORT}");
                let port_mapping = CString::new(port_mapping).unwrap();
                let port_map = [port_mapping.as_ptr(), null()];

                krun_call!(krun_set_port_map(ctx, port_map.as_ptr()))?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                setup_fs_and_enter(ctx, test_setup)?;
                println!("OK");
            }
            Ok(())
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

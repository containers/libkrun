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
    use crate::common::setup_fs_and_enter;
    use crate::{Test, TestSetup, krun_call, krun_call_u32};
    use krun_sys::*;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::ptr::null;
    use std::thread;

    impl Test for TestTsiTcpGuestListen {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                thread::spawn(move || {
                    self.tcp_tester.run_client();
                });

                krun_call!(krun_init_log(
                    KRUN_LOG_TARGET_DEFAULT,
                    KRUN_LOG_LEVEL_TRACE,
                    KRUN_LOG_STYLE_AUTO,
                    0
                ))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                let port_mapping = format!("{PORT}:{PORT}");
                let port_mapping = CString::new(port_mapping).unwrap();
                let port_map = [port_mapping.as_ptr(), null()];

                krun_call!(krun_add_vsock(ctx, KRUN_TSI_HIJACK_INET))?;
                krun_call!(krun_set_port_map(ctx, port_map.as_ptr()))?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;
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

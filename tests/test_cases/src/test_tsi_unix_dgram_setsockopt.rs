use macros::{guest, host};

/// Test that setsockopt works on TSI-intercepted Unix DGRAM sockets.
/// This is a regression test for a kernel NULL pointer dereference bug
/// in tsi_dgram_setsockopt that occurred when setting socket options.
///
/// The bug: tsi_dgram_setsockopt calls isocket->ops->setsockopt() for
/// SOL_SOCKET level options, but Unix sockets don't have a setsockopt
/// function in their proto_ops (it's NULL), causing a NULL pointer
/// dereference and kernel panic.
///
/// The fix uses sock_setsockopt() for SOL_SOCKET level options:
///   if (level == SOL_SOCKET) { sock_setsockopt(...) } else { isocket->ops->setsockopt(...) }
///
/// With an unfixed kernel, this test will cause the guest to kernel panic/hang.
/// With the fixed kernel, this test passes.
pub struct TestTsiUnixDgramSetsockopt;

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;

    impl Test for TestTsiUnixDgramSetsockopt {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_DEBUG))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use nix::libc;
    use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};
    use std::os::fd::AsRawFd;

    impl Test for TestTsiUnixDgramSetsockopt {
        fn in_guest(self: Box<Self>) {
            // Create a Unix DGRAM socket - this will be intercepted by TSI.
            // Unix sockets don't have proto_ops->setsockopt defined (it's NULL),
            // so calling isocket->ops->setsockopt() causes a NULL pointer deref.
            let socket =
                socket::socket(AddressFamily::Unix, SockType::Datagram, SockFlag::empty(), None)
                    .expect("Failed to create Unix DGRAM socket");

            // SOL_SOCKET level setsockopt calls trigger a kernel NULL pointer
            // dereference in the unfixed TSI code because Unix sockets don't
            // have a setsockopt function in their proto_ops.
            let optval: libc::c_int = 1;
            let ret = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                )
            };
            if ret != 0 {
                panic!(
                    "setsockopt SOL_SOCKET/SO_REUSEADDR failed: {}",
                    std::io::Error::last_os_error()
                );
            }

            // If we get here without a kernel panic, the test passed
            println!("OK");
        }
    }
}

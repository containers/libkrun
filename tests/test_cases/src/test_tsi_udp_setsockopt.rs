use crate::IpVersion;
use macros::{guest, host};

/// Test that setsockopt works on TSI-intercepted UDP sockets.
/// This is a regression test for a kernel NULL pointer dereference bug
/// in tsi_dgram_setsockopt that occurred when setting socket options
/// on UDP sockets before any sendto() call.
#[allow(dead_code)] // Used in guest module
pub struct TestTsiUdpSetsockopt {
    ip_version: IpVersion,
}

impl TestTsiUdpSetsockopt {
    pub fn new(ip_version: IpVersion) -> Self {
        Self { ip_version }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;

    impl Test for TestTsiUdpSetsockopt {
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
    use crate::IpVersion;
    use crate::Test;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket};

    impl Test for TestTsiUdpSetsockopt {
        fn in_guest(self: Box<Self>) {
            // Create a UDP socket - this will be intercepted by TSI
            let socket = match self.ip_version {
                IpVersion::V4 => UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                    .expect("Failed to bind UDP socket"),
                IpVersion::V6 => UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                    .expect("Failed to bind UDP socket"),
            };

            // These setsockopt calls triggered a kernel NULL pointer dereference
            // in the unfixed TSI code when called before any sendto().
            // The bug was at tsi_dgram_setsockopt where it dereferenced a NULL
            // proxy pointer.

            // Set nonblocking mode
            socket
                .set_nonblocking(false)
                .expect("set_nonblocking failed");

            // Set TTL
            socket.set_ttl(64).expect("set_ttl failed");

            // Set broadcast (IPv4 only)
            if self.ip_version == IpVersion::V4 {
                socket
                    .set_broadcast(true)
                    .expect("set_broadcast(true) failed");
                socket
                    .set_broadcast(false)
                    .expect("set_broadcast(false) failed");
            }

            // If we get here without a kernel panic, the test passed
            println!("OK");
        }
    }
}

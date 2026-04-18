//! FreeBSD guest-side utilities.

#[cfg(target_os = "freebsd")]
use nix::libc::{reboot, RB_NOSYNC};

/// Clean shutdown for FreeBSD guest tests.
///
/// After the guest test's `in_guest()` callback completes, call this to gracefully
/// halt the VM via `reboot(RB_NOSYNC)`. This avoids the init process panic
/// that would occur if PID 1's child simply exited.
#[cfg(target_os = "freebsd")]
pub fn halt_vm() -> ! {
    unsafe {
        reboot(RB_NOSYNC); // fast shutdown without syncing filesystems
    }
    loop {}
}

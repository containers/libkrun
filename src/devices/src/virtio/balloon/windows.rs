use windows_sys::Win32::System::Memory::DiscardVirtualMemory;

use super::device::FreeRange;

/// Gives the pages of free page reports back to the host with DiscardVirtualMemory().
#[derive(Default)]
pub(super) struct FreePageReclaim;

impl FreePageReclaim {
    /// Whether another report can be taken from the queue. Reports are released right away, so
    /// it always can.
    pub(super) fn can_take_report(&self) -> bool {
        true
    }

    /// Gives the pages of a report back to the host. That's done right away, so this returns
    /// false: the report can be used right away.
    pub(super) fn release(&mut self, _head: u16, ranges: Vec<FreeRange>) -> bool {
        for range in ranges {
            // SAFETY: the range is guest memory, whose contents the guest has given up.
            unsafe { DiscardVirtualMemory(range.host_addr.cast(), range.len) };
        }
        false
    }
}

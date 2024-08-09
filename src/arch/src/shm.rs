use crate::round_up;

use super::ArchMemoryInfo;
#[derive(Debug)]
pub enum Error {
    OutOfSpace,
}

#[derive(Clone)]
pub struct ShmRegion {
    pub guest_addr: u64,
    pub size: usize,
}

pub struct ShmManager {
    next_guest_addr: u64,
    page_size: usize,
}

impl ShmManager {
    pub fn new(info: &ArchMemoryInfo) -> ShmManager {
        Self {
            next_guest_addr: info.shm_start_addr,
            page_size: info.page_size,
        }
    }

    pub fn get_region(&mut self, size: usize) -> Result<ShmRegion, Error> {
        let size = round_up(size, self.page_size);

        let region = ShmRegion {
            guest_addr: self.next_guest_addr,
            size,
        };

        if let Some(addr) = self.next_guest_addr.checked_add(size as u64) {
            self.next_guest_addr = addr;
            Ok(region)
        } else {
            Err(Error::OutOfSpace)
        }
    }
}

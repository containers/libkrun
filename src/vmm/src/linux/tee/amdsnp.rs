use std::os::unix::io::{AsRawFd, RawFd};

use crate::vstate::MeasuredRegion;

use sev::firmware::uapi::host::Firmware;
use sev::launch::snp::*;

use kvm_bindings::kvm_enc_region;
use kvm_ioctls::VmFd;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap};

#[derive(Debug)]
pub enum Error {
    OpenFirmware(std::io::Error),
    CreateLauncher(std::io::Error),
    MemoryEncryptRegion,
    LaunchStart(std::io::Error),
    LaunchUpdate(std::io::Error),
    LaunchFinish(std::io::Error),
    CpuIdWrite,
}

pub struct AmdSnp {
    fw: Firmware,
}

impl AmdSnp {
    pub fn new() -> Result<Self, Error> {
        let fw = Firmware::open().map_err(Error::OpenFirmware)?;

        Ok(AmdSnp { fw })
    }

    pub fn vm_prepare(
        &self,
        vm_fd: &VmFd,
        guest_mem: &GuestMemoryMmap,
    ) -> Result<Launcher<Started, RawFd, RawFd>, Error> {
        let vm_rfd = vm_fd.as_raw_fd();
        let fw_rfd = self.fw.as_raw_fd();

        let launcher = Launcher::new(vm_rfd, fw_rfd).map_err(Error::CreateLauncher)?;

        for region in guest_mem.iter() {
            // It's safe to unwrap because the guest address is valid.
            let host_addr = guest_mem.get_host_address(region.start_addr()).unwrap();
            let enc_region = kvm_enc_region {
                addr: host_addr as u64,
                size: region.len() as u64,
            };

            vm_fd
                .register_enc_memory_region(&enc_region)
                .map_err(|_| Error::MemoryEncryptRegion)?;
        }

        let start = Start::new(
            None,
            Policy {
                flags: PolicyFlags::SMT,
                ..Default::default()
            },
            false,
            [0; 16],
        );

        let launcher = launcher.start(start).map_err(Error::LaunchStart)?;

        Ok(launcher)
    }

    pub fn vm_measure(
        &self,
        guest_mem: &GuestMemoryMmap,
        measured_regions: Vec<MeasuredRegion>,
        mut launcher: Launcher<Started, RawFd, RawFd>,
    ) -> Result<(), Error> {
        let dp = VmplPerms::empty();
        for region in measured_regions {
            let page_type = if region.guest_addr == arch::x86_64::layout::ZERO_PAGE_START {
                PageType::Zero
            } else {
                PageType::Normal
            };

            let ga = GuestAddress(region.guest_addr);

            /*
             * Use the guest's address to obtain its GuestRegionMmap, and then
             * convert this region to a slice. Basically, we are taking an
             * entire slice of a guest memory region.
             */
            let gr: &GuestRegionMmap = guest_mem.find_region(ga).unwrap();
            let region_slice = unsafe { gr.as_slice().unwrap() };

            /*
             * The memory region we are currently looking to measure is
             * represented simply as a guest address at the moment. Instead,
             * we would like to obtain a slice of it. To do this, we must use
             * the guest address as an OFFSET within the slice, and only take
             * that subslice.
             */
            let offset: usize = guest_mem
                .to_region_addr(ga)
                .unwrap()
                .1
                 .0
                .try_into()
                .unwrap();

            /*
             * We know the size of the region to be measured from the
             * MeasuredRegion.
             */
            let count: usize = region.size;

            /*
             * We now have the start and end indexes of the slice, so use these
             * indexes to take a subslice of the guest region (corresponding to
             * the slice of bytes that we're looking to measure).
             */
            let buf = &region_slice[offset..offset + count];

            /*
             * From that subslice, build an Update struct and call
             * SNP_LAUNCH_UPDATE.
             */
            let update = Update::new(region.guest_addr >> 12, buf, false, page_type, (dp, dp, dp));

            launcher.update_data(update).map_err(Error::LaunchUpdate)?;
        }

        let finish = Finish::new(None, None, [0; 32]);

        let (_vmfd, _fwfd) = launcher.finish(finish).map_err(Error::LaunchFinish)?;

        Ok(())
    }
}

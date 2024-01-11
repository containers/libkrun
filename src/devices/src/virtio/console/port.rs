//! See https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-2920002
//! for port <-> virtio queue index mapping

use std::io;

use std::os::fd::{AsRawFd, RawFd};

use crate::virtio::console::device::PortDescription;
use crate::virtio::console::port_io::{PortInput, PortOutput};
use crate::virtio::Queue;
use vm_memory::{
    GuestMemory, GuestMemoryMmap, GuestMemoryRegion, ReadVolatile, VolatileMemoryError,
    WriteVolatile,
};

#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum PortStatus {
    NotReady,
    Ready { opened: bool },
}

pub(crate) struct Port {
    pub(crate) status: PortStatus,
    pub(crate) input: PortInput,
    pub(crate) output: PortOutput,
}

impl Port {
    pub(crate) fn new(description: PortDescription) -> Self {
        match description {
            PortDescription::Console { input, output } => Self {
                status: PortStatus::NotReady,
                input,
                output,
            },
        }
    }

    pub fn input_rawfd(&self) -> RawFd {
        self.input.as_raw_fd()
    }

    pub fn process_rx(&mut self, mem: &GuestMemoryMmap, queue: &mut Queue) -> bool {
        let mut raise_irq = false;

        while let Some(head) = queue.pop(mem) {
            let result = mem.try_access(head.len as usize, head.addr, |_, len, addr, region| {
                let mut target = region.get_slice(addr, len).unwrap();
                let result = self.input.read_volatile(&mut target);
                log::trace!("}} read");
                match result {
                    Ok(n) => Ok(n),
                    // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                    Err(VolatileMemoryError::IOError(e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        Ok(0)
                    }
                    Err(e) => Err(e.into()),
                }
            });

            match result {
                Ok(0) => {
                    log::trace!("Rx EOF/WouldBlock");
                    queue.undo_pop();
                    break;
                }
                Ok(len) => {
                    log::trace!("Rx {len} bytes");
                    queue.add_used(mem, head.index, len as u32);
                    raise_irq = true;
                }
                Err(e) => {
                    log::error!("Failed to read: {e:?}")
                }
            }
        }

        raise_irq
    }

    pub fn process_tx(&mut self, mem: &GuestMemoryMmap, queue: &mut Queue) -> bool {
        let mut raise_irq = false;
        log::trace!("process_tx");
        while let Some(head) = queue.pop(mem) {
            let src = mem.get_slice(head.addr, head.len as usize).unwrap();
            let mut tmp: Vec<u8> = Vec::new();
            tmp.write_volatile(&src).unwrap();
            log::trace!("write {{");
            let result = self.output.write_volatile(&src);
            log::trace!("}} write");
            log::trace!(
                "Output result: {:?} (\"{}\") {:x?}",
                result,
                String::from_utf8_lossy(&tmp),
                tmp
            );
            match result {
                Ok(n) => {
                    //TODO: ablity to finish writing the rest
                    queue.add_used(mem, head.index, n as u32)
                }
                Err(e) => {
                    log::error!("Failed to write output: {e}");
                }
            }
            raise_irq = true;
        }

        raise_irq
    }
}

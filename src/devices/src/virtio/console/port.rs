//! See https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-2920002
//! for port <-> virtio queue index mapping

use std::borrow::Cow;
use std::io;

use std::os::fd::{AsRawFd, RawFd};

use crate::virtio::console::device::PortDescription;
use crate::virtio::console::port_io::{PortInput, PortOutput};
use crate::virtio::Queue;
use vm_memory::{
    Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, ReadVolatile,
    VolatileMemoryError, WriteVolatile,
};

#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum PortStatus {
    NotReady,
    Ready { opened: bool },
}

struct UnfinishedDescriptorChain {
    addr: GuestAddress,
    len: u32,
    index: u16,
}

pub(crate) struct Port {
    /// Empty if no name given
    pub(crate) name: Cow<'static, str>,
    pub(crate) status: PortStatus,
    pub(crate) input: Option<PortInput>,
    pub(crate) pending_input: bool,
    pub(crate) pending_eof: bool,
    pub(crate) output: Option<PortOutput>,
    unfinished_output: Option<UnfinishedDescriptorChain>,
    pub(crate) represents_console: bool,
}

impl Port {
    pub(crate) fn new(description: PortDescription) -> Self {
        match description {
            PortDescription::Console { input, output } => Self {
                name: "".into(),
                represents_console: true,
                status: PortStatus::NotReady,
                input,
                pending_input: false,
                pending_eof: false,
                output: Some(output),
                unfinished_output: None,
            },
            PortDescription::InputPipe { name, input } => Self {
                name,
                status: PortStatus::NotReady,
                input: Some(input),
                pending_input: false,
                pending_eof: false,
                output: None,
                represents_console: false,
                unfinished_output: None,
            },
        }
    }

    pub fn input_rawfd(&self) -> Option<RawFd> {
        self.input.as_ref().map(|inp| inp.as_raw_fd())
    }

    pub fn output_rawfd(&self) -> Option<RawFd> {
        self.output.as_ref().map(|out| out.as_raw_fd())
    }

    pub fn has_pending_output(&self) -> bool {
        self.unfinished_output.is_some()
    }

    pub fn process_rx(&mut self, mem: &GuestMemoryMmap, queue: &mut Queue) -> bool {
        let mut raise_irq = false;

        let Some(input) = &mut self.input else {
            return raise_irq;
        };

        while let Some(head) = queue.pop(mem) {
            let result = mem.try_access(head.len as usize, head.addr, |_, len, addr, region| {
                let mut target = region.get_slice(addr, len).unwrap();
                let result = input.read_volatile(&mut target);
                log::trace!("}} read");
                match result {
                    Ok(n) => {
                        if n == 0 {
                            self.pending_input = false;
                        }
                        Ok(n)
                    }
                    // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                    Err(VolatileMemoryError::IOError(e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        self.pending_input = false;
                        Ok(0)
                    }
                    Err(e) => Err(e.into()),
                }
            });
            raise_irq = true;
            match result {
                Ok(0) => {
                    log::trace!("Rx EOF/WouldBlock");
                    queue.undo_pop();
                    break;
                }
                Ok(len) => {
                    log::trace!("Rx {len} bytes");
                    queue.add_used(mem, head.index, len as u32);
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

        let Some(output) = &mut self.output else {
            return raise_irq;
        };

        loop {
            let (addr, len, index) = if let Some(out) = &self.unfinished_output {
                (out.addr, out.len, out.index)
            } else if let Some(head) = queue.pop(mem) {
                (head.addr, head.len, head.index)
            } else {
                break;
            };

            let result = mem.try_access(len as usize, addr, |_, len, addr, region| {
                let src = region.get_slice(addr, len).unwrap();
                let result = output.write_volatile(&src);

                match result {
                    // try_access seem to handle partial write for us (we will be invoked again with an offset)
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
                    log::trace!("Tx EOF/WouldBlock");
                    queue.undo_pop();
                    break;
                }
                Ok(n) => {
                    if n == len as usize {
                        self.unfinished_output = None;
                        queue.add_used(mem, index, n as u32)
                    } else {
                        assert!(n < len as usize);
                        self.unfinished_output = Some(UnfinishedDescriptorChain {
                            addr: addr.checked_add(n as u64).expect("Guest address overflow!"),
                            len: len - n as u32,
                            index,
                        })
                    }
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

use std::sync::Arc;
use std::{io, thread};

use vm_memory::{GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion};

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::irq_signaler::IRQSignaler;
use crate::virtio::console::port_io::PortInput;
use crate::virtio::{DescriptorChain, Queue};

pub(crate) fn process_rx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    irq: IRQSignaler,
    mut input: Box<dyn PortInput + Send>,
    control: Arc<ConsoleControl>,
    port_id: u32,
) {
    let mem = &mem;
    let mut eof = false;

    loop {
        let head = pop_head_blocking(&mut queue, mem, &irq);

        let head_index = head.index;
        let mut bytes_read = 0;
        for chain in head.into_iter().writable() {
            match read_to_desc(chain, input.as_mut(), &mut eof) {
                Ok(0) => {
                    break;
                }
                Ok(len) => {
                    bytes_read += len;
                }
                Err(e) => {
                    log::error!("Failed to read: {e:?}")
                }
            }
        }

        if bytes_read != 0 {
            log::trace!("Rx {bytes_read} bytes queue len{}", queue.len(mem));
            queue.add_used(mem, head_index, bytes_read as u32);
        }

        // We signal_used_queue only when we get WouldBlock or EOF
        if eof {
            irq.signal_used_queue("rx EOF");
            log::trace!("signaling EOF on port {port_id}");
            control.port_open(port_id, false);
            return;
        } else if bytes_read == 0 {
            queue.undo_pop();
            irq.signal_used_queue("rx WouldBlock");
            input.wait_until_readable();
        }
    }
}

fn pop_head_blocking<'mem>(
    queue: &mut Queue,
    mem: &'mem GuestMemoryMmap,
    irq: &IRQSignaler,
) -> DescriptorChain<'mem> {
    loop {
        match queue.pop(mem) {
            Some(descriptor) => break descriptor,
            None => {
                irq.signal_used_queue("rx queue empty, parking");
                thread::park();
                log::trace!("rx unparked, queue len {}", queue.len(mem))
            }
        }
    }
}

fn read_to_desc(
    desc: DescriptorChain,
    input: &mut (dyn PortInput + Send),
    eof: &mut bool,
) -> Result<usize, GuestMemoryError> {
    desc.mem
        .try_access(desc.len as usize, desc.addr, |_, len, addr, region| {
            let mut target = region.get_slice(addr, len).unwrap();
            match input.read_volatile(&mut target) {
                Ok(n) => {
                    if n == 0 {
                        *eof = true
                    }
                    Ok(n)
                }
                // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(GuestMemoryError::IOError(e)),
            }
        })
}

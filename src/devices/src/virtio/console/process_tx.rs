use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{io, thread};

use vm_memory::{GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion};

use crate::virtio::console::irq_signaler::IRQSignaler;
use crate::virtio::console::port_io::PortOutput;
use crate::virtio::{DescriptorChain, Queue};

pub(crate) fn process_tx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    irq: IRQSignaler,
    mut output: Box<dyn PortOutput + Send>,
    stop: Arc<AtomicBool>,
) {
    loop {
        let Some(head) = pop_head_blocking(&mut queue, &mem, &irq, &stop) else {
            return;
        };

        let head_index = head.index;
        let mut bytes_written = 0;

        for desc in head.into_iter().readable() {
            let desc_len = desc.len as usize;
            match write_desc_to_output(desc, output.as_mut(), &irq) {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    assert_eq!(n, desc_len);
                    bytes_written += n;
                }
                Err(e) => {
                    log::error!("Failed to write output: {e}");
                }
            }
        }

        if bytes_written == 0 {
            log::trace!("Tx Add used {bytes_written}");
            queue.undo_pop();
        } else {
            log::trace!("Tx add used {bytes_written}");
            queue.add_used(&mem, head_index, bytes_written as u32);
        }
    }
}

fn pop_head_blocking<'mem>(
    queue: &mut Queue,
    mem: &'mem GuestMemoryMmap,
    irq: &IRQSignaler,
    stop: &AtomicBool,
) -> Option<DescriptorChain<'mem>> {
    loop {
        match queue.pop(mem) {
            Some(descriptor) => break Some(descriptor),
            None => {
                irq.signal_used_queue("tx queue empty, parking");
                thread::park();
                if stop.load(Ordering::Acquire) {
                    break None;
                }
                log::trace!("tx unparked, queue len {}", queue.len(mem))
            }
        }
    }
}

fn write_desc_to_output(
    desc: DescriptorChain,
    output: &mut (dyn PortOutput + Send),
    irq: &IRQSignaler,
) -> Result<usize, GuestMemoryError> {
    desc.mem
        .try_access(desc.len as usize, desc.addr, |_, len, addr, region| {
            let src = region.get_slice(addr, len).unwrap();
            loop {
                log::trace!("Tx {:?}, write_volatile {len} bytes", src);
                match output.write_volatile(&src) {
                    // try_access seem to handle partial write for us (we will be invoked again with an offset)
                    Ok(n) => break Ok(n),
                    // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        log::trace!("Tx wait for output (would block)");
                        irq.signal_used_queue("tx waiting for output");
                        output.wait_until_writable();
                    }
                    Err(e) => break Err(GuestMemoryError::IOError(e)),
                }
            }
        })
}

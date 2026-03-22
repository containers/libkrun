use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, thread};

use vm_memory::{GuestMemory, GuestMemoryError, GuestMemoryMmap};

use crate::virtio::console::port_io::PortOutput;
use crate::virtio::{DescriptorChain, InterruptTransport, Queue};

pub(crate) fn process_tx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    interrupt: InterruptTransport,
    output: Arc<Mutex<Box<dyn PortOutput + Send>>>,
    stop: Arc<AtomicBool>,
) {
    loop {
        let Some(head) = pop_head_blocking(&mut queue, &mem, &interrupt, &stop) else {
            return;
        };

        let head_index = head.index;
        let mut bytes_written = 0;

        for desc in head.into_iter().readable() {
            let desc_len = desc.len as usize;
            match write_desc_to_output(desc, output.lock().unwrap().as_mut(), &interrupt) {
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
            if let Err(e) = queue.add_used(&mem, head_index, bytes_written as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
    }
}

fn pop_head_blocking<'mem>(
    queue: &mut Queue,
    mem: &'mem GuestMemoryMmap,
    interrupt: &InterruptTransport,
    stop: &AtomicBool,
) -> Option<DescriptorChain<'mem>> {
    loop {
        match queue.pop(mem) {
            Some(descriptor) => break Some(descriptor),
            None => {
                interrupt.signal_used_queue();
                if stop.load(Ordering::Acquire) {
                    break None;
                }
                thread::park();
                log::trace!("tx unparked, queue len {}", queue.len(mem))
            }
        }
    }
}

fn write_desc_to_output(
    desc: DescriptorChain,
    output: &mut (dyn PortOutput + Send),
    interrupt: &InterruptTransport,
) -> Result<usize, GuestMemoryError> {
    let mut total = 0;
    for slice in desc.mem.get_slices(desc.addr, desc.len as usize) {
        let slice = slice?;
        loop {
            log::trace!("Tx {slice:?}, write_volatile {} bytes", slice.len());
            match output.write_volatile(&slice) {
                Ok(n) => {
                    total += n;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    log::trace!("Tx wait for output (would block)");
                    interrupt.signal_used_queue();
                    output.wait_until_writable();
                }
                Err(e) => return Err(GuestMemoryError::IOError(e)),
            }
        }
    }
    Ok(total)
}

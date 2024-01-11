use crate::virtio::console::defs::control_event::{
    VIRTIO_CONSOLE_CONSOLE_PORT, VIRTIO_CONSOLE_PORT_ADD,
};
use crate::virtio::Queue as VirtQueue;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap};

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed(4))]
pub struct VirtioConsoleControl {
    /// Port number
    pub id: u32,
    /// The kind of control event
    pub event: u16,
    /// Extra information for the event
    pub value: u16,
}

// Safe because it only has data and has no implicit padding.
// But NOTE that this relies on CPU being little endian, to have correct semantics
unsafe impl ByteValued for VirtioConsoleControl {}

// Utility for sending commands into control rx queue
pub struct ConsoleControlSender<'a> {
    queue: &'a mut VirtQueue,
}

impl<'a> ConsoleControlSender<'a> {
    pub fn new(control_rx_queue: &'a mut VirtQueue) -> Self {
        return ConsoleControlSender {
            queue: control_rx_queue,
        };
    }

    pub fn send_mark_console_port(&mut self, mem: &GuestMemoryMmap, port_id: u32) {
        self.send_cmd(
            mem,
            &VirtioConsoleControl {
                id: port_id,
                event: VIRTIO_CONSOLE_CONSOLE_PORT,
                value: 1,
            },
        )
    }

    /// Adds another port with the specified port_id
    pub fn send_port_add(&mut self, mem: &GuestMemoryMmap, port_id: u32) {
        self.send_cmd(
            mem,
            &VirtioConsoleControl {
                id: port_id,
                event: VIRTIO_CONSOLE_PORT_ADD,
                value: 0,
            },
        )
    }

    fn send_bytes(&mut self, mem: &GuestMemoryMmap, data: &[u8]) {
        if let Some(head) = self.queue.pop(mem) {
            if let Err(e) = mem.write_slice(data, head.addr) {
                log::error!("Failed to write to tx_control_queue: {e:?}");
            }
            self.queue.add_used(mem, head.index, data.len() as u32);
        } else {
            log::error!("Failed to write to tx_control_queue: no space in queue");
        }
    }

    fn send_cmd(&mut self, mem: &GuestMemoryMmap, cmd: &VirtioConsoleControl) {
        self.send_bytes(mem, cmd.as_slice())
    }
}

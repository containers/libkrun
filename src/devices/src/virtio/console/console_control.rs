use crate::virtio::console::defs::control_event::{
    VIRTIO_CONSOLE_CONSOLE_PORT, VIRTIO_CONSOLE_PORT_ADD, VIRTIO_CONSOLE_RESIZE,
};
use crate::virtio::Queue as VirtQueue;
use std::mem::size_of;
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

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleResize {
    // The order of these fields in the kernel and in the spec do not match
    pub rows: u16,
    pub cols: u16,
}

// Safe because it only has data and has no implicit padding.
// but NOTE, that we rely on CPU being little endian, for the values to be correct
unsafe impl ByteValued for VirtioConsoleResize {}

// Utility for sending commands into control rx queue
pub struct ConsoleControlSender<'a> {
    queue: &'a mut VirtQueue,
}

impl<'a> ConsoleControlSender<'a> {
    pub fn new(control_rx_queue: &'a mut VirtQueue) -> Self {
        ConsoleControlSender {
            queue: control_rx_queue,
        }
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

    pub fn send_console_resize(
        &mut self,
        mem: &GuestMemoryMmap,
        port_id: u32,
        new_size: &VirtioConsoleResize,
    ) {
        let resize_cmd = VirtioConsoleControl {
            id: port_id,
            event: VIRTIO_CONSOLE_RESIZE,
            value: 0,
        };

        const SIZE_1: usize = size_of::<VirtioConsoleControl>();
        const SIZE_2: usize = size_of::<VirtioConsoleResize>();
        let mut data = [0u8; SIZE_1 + SIZE_2];
        data[..SIZE_1].copy_from_slice(resize_cmd.as_slice());
        data[SIZE_1..].copy_from_slice(new_size.as_slice());
        self.send_bytes(mem, data.as_slice());
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

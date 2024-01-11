//! See https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-2920002
//! for port <-> virtio queue index mapping

use std::sync::Arc;
use std::thread::JoinHandle;
use std::{mem, thread};

use vm_memory::GuestMemoryMmap;

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::irq_signaler::IRQSignaler;
use crate::virtio::console::port_io::{PortInput, PortOutput};
use crate::virtio::console::process_rx::process_rx;
use crate::virtio::console::process_tx::process_tx;
use crate::virtio::Queue;

pub enum PortDescription {
    Console {
        input: Option<Box<dyn PortInput + Send>>,
        output: Option<Box<dyn PortOutput + Send>>,
    },
}

enum PortState {
    Inactive {
        input: Option<Box<dyn PortInput + Send>>,
        output: Option<Box<dyn PortOutput + Send>>,
    },
    Active {
        rx_thread: Option<JoinHandle<()>>,
        tx_thread: Option<JoinHandle<()>>,
    },
}

pub(crate) struct Port {
    port_id: u32,
    state: PortState,
}

impl Port {
    pub(crate) fn new(port_id: u32, description: PortDescription) -> Self {
        match description {
            PortDescription::Console { input, output } => Self {
                port_id,
                state: PortState::Inactive { input, output },
            },
        }
    }

    pub fn notify_rx(&self) {
        if let PortState::Active {
            rx_thread: Some(handle),
            ..
        } = &self.state
        {
            handle.thread().unpark()
        }
    }

    pub fn notify_tx(&self) {
        if let PortState::Active {
            tx_thread: Some(handle),
            ..
        } = &self.state
        {
            handle.thread().unpark()
        }
    }

    pub fn start(
        &mut self,
        mem: GuestMemoryMmap,
        rx_queue: Queue,
        tx_queue: Queue,
        irq_signaler: IRQSignaler,
        control: Arc<ConsoleControl>,
    ) {
        let (input, output) = if let PortState::Inactive { input, output } = &mut self.state {
            (mem::take(input), mem::take(output))
        } else {
            // The threads are already started
            return;
        };

        let rx_thread = input.map(|input| {
            let mem = mem.clone();
            let irq_signaler = irq_signaler.clone();
            let port_id = self.port_id;
            thread::spawn(move || process_rx(mem, rx_queue, irq_signaler, input, control, port_id))
        });

        let tx_thread = output
            .map(|output| thread::spawn(move || process_tx(mem, tx_queue, irq_signaler, output)));

        self.state = PortState::Active {
            rx_thread,
            tx_thread,
        }
    }
}

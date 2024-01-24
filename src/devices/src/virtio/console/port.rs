use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
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
    InputPipe {
        name: Cow<'static, str>,
        input: Box<dyn PortInput + Send>,
    },
    OutputPipe {
        name: Cow<'static, str>,
        output: Box<dyn PortOutput + Send>,
    },
}

enum PortState {
    Inactive {
        input: Option<Box<dyn PortInput + Send>>,
        output: Option<Box<dyn PortOutput + Send>>,
    },
    Active {
        stop: Arc<AtomicBool>,
        rx_thread: Option<JoinHandle<()>>,
        tx_thread: Option<JoinHandle<()>>,
    },
}

pub(crate) struct Port {
    port_id: u32,
    /// Empty if no name given
    name: Cow<'static, str>,
    represents_console: bool,
    state: PortState,
}

impl Port {
    pub(crate) fn new(port_id: u32, description: PortDescription) -> Self {
        match description {
            PortDescription::Console { input, output } => Self {
                port_id,
                name: "".into(),
                represents_console: true,
                state: PortState::Inactive { input, output },
            },
            PortDescription::InputPipe { name, input } => Self {
                port_id,
                name,
                represents_console: false,
                state: PortState::Inactive {
                    input: Some(input),
                    output: None,
                },
            },
            PortDescription::OutputPipe { name, output } => Self {
                port_id,
                name,
                represents_console: false,
                state: PortState::Inactive {
                    input: None,
                    output: Some(output),
                },
            },
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_console(&self) -> bool {
        self.represents_console
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

        let stop = Arc::new(AtomicBool::new(false));
        let tx_thread = output.map(|output| {
            let stop = stop.clone();
            thread::spawn(move || process_tx(mem, tx_queue, irq_signaler, output, stop))
        });

        self.state = PortState::Active {
            stop,
            rx_thread,
            tx_thread,
        }
    }

    pub fn flush(&mut self) {
        if let PortState::Active {
            stop,
            tx_thread,
            rx_thread: _,
        } = &mut self.state
        {
            stop.store(true, Ordering::Release);
            if let Some(tx_thread) = mem::take(tx_thread) {
                tx_thread.thread().unpark();
                if let Err(e) = tx_thread.join() {
                    log::error!(
                        "Failed to flush tx for port {port_id}, thread panicked: {e:?}",
                        port_id = self.port_id
                    )
                }
            }
        };
    }
}

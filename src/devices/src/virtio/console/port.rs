use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::{mem, thread};

use vm_memory::GuestMemoryMmap;

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::port_io::{PortInput, PortOutput};
use crate::virtio::console::process_rx::process_rx;
use crate::virtio::console::process_tx::process_tx;
use crate::virtio::{InterruptTransport, Queue};

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
    Inactive,
    Active {
        stopfd: utils::eventfd::EventFd,
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
    input: Option<Arc<Mutex<Box<dyn PortInput + Send>>>>,
    output: Option<Arc<Mutex<Box<dyn PortOutput + Send>>>>,
}

impl Port {
    pub(crate) fn new(port_id: u32, description: PortDescription) -> Self {
        match description {
            PortDescription::Console { input, output } => Self {
                port_id,
                name: "".into(),
                represents_console: true,
                state: PortState::Inactive,
                input: Some(Arc::new(Mutex::new(input.unwrap()))),
                output: Some(Arc::new(Mutex::new(output.unwrap()))),
            },
            PortDescription::InputPipe { name, input } => Self {
                port_id,
                name,
                represents_console: false,
                state: PortState::Inactive,
                input: Some(Arc::new(Mutex::new(input))),
                output: None,
            },
            PortDescription::OutputPipe { name, output } => Self {
                port_id,
                name,
                represents_console: false,
                state: PortState::Inactive,
                input: None,
                output: Some(Arc::new(Mutex::new(output))),
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
        interrupt: InterruptTransport,
        control: Arc<ConsoleControl>,
    ) {
        if let PortState::Active { .. } = &mut self.state {
            self.shutdown();
        };

        let input = self.input.as_ref().cloned();
        let output = self.output.as_ref().cloned();

        let stopfd = utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK)
            .expect("Failed to create EventFd for interrupt_evt");
        let stop = Arc::new(AtomicBool::new(false));

        let rx_thread = input.map(|input| {
            let mem = mem.clone();
            let interrupt = interrupt.clone();
            let port_id = self.port_id;
            let stopfd = stopfd.try_clone().unwrap();
            let stop = stop.clone();
            thread::Builder::new()
                .name("console port".into())
                .spawn(move || {
                    process_rx(
                        mem, rx_queue, interrupt, input, control, port_id, stopfd, stop,
                    )
                })
                .unwrap()
        });

        let tx_thread = output.map(|output| {
            let stop = stop.clone();
            thread::spawn(move || process_tx(mem, tx_queue, interrupt, output, stop))
        });

        self.state = PortState::Active {
            stopfd,
            stop,
            rx_thread,
            tx_thread,
        }
    }

    pub fn shutdown(&mut self) {
        if let PortState::Active {
            stopfd,
            stop,
            tx_thread,
            rx_thread,
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
            stopfd.write(1).unwrap();
            if let Some(rx_thread) = mem::take(rx_thread) {
                rx_thread.thread().unpark();
                if let Err(e) = rx_thread.join() {
                    log::error!(
                        "Failed to flush tx for port {port_id}, thread panicked: {e:?}",
                        port_id = self.port_id
                    )
                }
            }
        };
    }
}

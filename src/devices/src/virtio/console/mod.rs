mod console_control;
mod device;
mod event_handler;
mod port;
mod port_io;
mod port_queue_mapping;

pub use self::defs::uapi::VIRTIO_ID_CONSOLE as TYPE_CONSOLE;
pub use self::device::{Console, PortDescription};
pub use self::port_io::{PortInput, PortOutput};

mod defs {
    pub const CONSOLE_DEV_ID: &str = "virtio_console";
    pub const QUEUE_SIZE: u16 = 256;

    pub mod uapi {
        /// The device conforms to the virtio spec version 1.0.
        pub const VIRTIO_CONSOLE_F_SIZE: u32 = 0;
        pub const VIRTIO_CONSOLE_F_MULTIPORT: u32 = 1;
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_CONSOLE: u32 = 3;
    }

    #[allow(dead_code)]
    pub mod control_event {
        pub const VIRTIO_CONSOLE_DEVICE_READY: u16 = 0;
        // Also known as VIRTIO_CONSOLE_DEVICE_ADD in spec, but kernel uses this (more descriptive) name
        pub const VIRTIO_CONSOLE_PORT_ADD: u16 = 1;
        /// Also known as VIRTIO_CONSOLE_DEVICE_REMOVE in spec, but kernel uses this (more descriptive) name
        pub const VIRTIO_CONSOLE_PORT_REMOVE: u16 = 2;
        pub const VIRTIO_CONSOLE_PORT_READY: u16 = 3;
        pub const VIRTIO_CONSOLE_CONSOLE_PORT: u16 = 4;
        pub const VIRTIO_CONSOLE_RESIZE: u16 = 5;
        pub const VIRTIO_CONSOLE_PORT_OPEN: u16 = 6;
        pub const VIRTIO_CONSOLE_PORT_NAME: u16 = 7;
    }
}

#[derive(Debug)]
pub enum ConsoleError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// Failed to create SIGWINCH pipe.
    SigwinchPipe(std::io::Error),
}

type Result<T> = std::result::Result<T, ConsoleError>;

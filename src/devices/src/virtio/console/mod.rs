mod device;
mod event_handler;

pub use self::defs::uapi::VIRTIO_ID_CONSOLE as TYPE_CONSOLE;
pub use self::device::Console;

mod defs {
    pub const CONSOLE_DEV_ID: &str = "virtio_console";
    pub const NUM_QUEUES: usize = 2;
    pub const QUEUE_SIZES: &[u16] = &[256; NUM_QUEUES];

    pub mod uapi {
        /// The device conforms to the virtio spec version 1.0.
        pub const VIRTIO_CONSOLE_F_SIZE: u32 = 0;
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_CONSOLE: u32 = 3;
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

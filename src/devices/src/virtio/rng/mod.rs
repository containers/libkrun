mod device;
mod event_handler;

pub use self::defs::uapi::VIRTIO_ID_RNG as TYPE_RNG;
pub use self::device::Rng;

mod defs {
    pub const RNG_DEV_ID: &str = "virtio_rng";
    pub const NUM_QUEUES: usize = 1;
    pub const QUEUE_SIZES: &[u16] = &[256; NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_RNG: u32 = 4;
    }
}

#[derive(Debug)]
pub enum RngError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
}

type Result<T> = std::result::Result<T, RngError>;

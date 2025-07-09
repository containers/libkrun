mod device;
pub mod display;
mod event_handler;
mod protocol;
mod virtio_gpu;
mod worker;

use super::descriptor_utils::Error as DescriptorError;

pub use self::defs::uapi::VIRTIO_ID_GPU as TYPE_GPU;
pub use self::device::Gpu;
use crate::virtio::gpu::protocol::{
    VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM, VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM,
    VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM, VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
    VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM, VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM,
    VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM, VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM,
};

mod defs {
    pub const GPU_DEV_ID: &str = "virtio_gpu";
    pub const NUM_QUEUES: usize = 2;
    pub const QUEUE_SIZES: &[u16] = &[256; NUM_QUEUES];

    #[allow(dead_code)]
    pub mod uapi {
        use vm_memory::ByteValued;

        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_GPU: u32 = 16;

        pub const VIRTIO_GPU_F_VIRGL: u32 = 0;
        pub const VIRTIO_GPU_F_EDID: u32 = 1;
        pub const VIRTIO_GPU_F_RESOURCE_UUID: u32 = 2;
        pub const VIRTIO_GPU_F_RESOURCE_BLOB: u32 = 3;
        pub const VIRTIO_GPU_F_CONTEXT_INIT: u32 = 4;
        /* The following capabilities are not upstreamed. */
        pub const VIRTIO_GPU_F_RESOURCE_SYNC: u32 = 5;
        pub const VIRTIO_GPU_F_CREATE_GUEST_HANDLE: u32 = 6;

        #[derive(Copy, Clone, Debug, Default)]
        #[repr(C)]
        pub struct virtio_gpu_config {
            pub events_read: u32,
            pub events_clear: u32,
            pub num_scanouts: u32,
            pub num_capsets: u32,
        }
        unsafe impl ByteValued for virtio_gpu_config {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GpuResourceFormat {
    BGRA = VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
    BGRX = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
    ARGB = VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM,
    XRGB = VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM,
    RGBA = VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
    XBGR = VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM,
    ABGR = VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM,
    RGBX = VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM,
}

impl GpuResourceFormat {
    // This is true for all exiting formats, hence we can hardcode it here
    const BYTES_PER_PIXEL: u32 = 4;
}

impl TryFrom<u32> for GpuResourceFormat {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM => Ok(Self::BGRA),
            VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM => Ok(Self::BGRX),
            VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM => Ok(Self::ARGB),
            VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM => Ok(Self::XRGB),
            VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM => Ok(Self::RGBA),
            VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM => Ok(Self::XBGR),
            VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM => Ok(Self::ABGR),
            VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM => Ok(Self::RGBX),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
pub enum GpuError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// Failed to decode incoming command.
    DecodeCommand(std::io::Error),
    /// Error creating Reader for Queue.
    QueueReader(DescriptorError),
    /// Error creating Writer for Queue.
    QueueWriter(DescriptorError),
    /// Error writting to the Queue.
    WriteDescriptor(std::io::Error),
    /// Error reading Guest Memory,
    GuestMemory,
}

type Result<T> = std::result::Result<T, GpuError>;

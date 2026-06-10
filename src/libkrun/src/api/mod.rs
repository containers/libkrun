pub mod devices;
pub mod error;
pub mod logging;
pub mod payload;
pub mod vmm_builder;

// Re-export from the external `devices` (krun-devices) crate.
// Can't use `devices::` here because `pub mod devices` above shadows it.
pub use crate::reexports::port_io;
pub use crate::reexports::TsiFlags;
#[cfg(feature = "net")]
pub use crate::reexports::VirtioNetBackend;

#[cfg(feature = "blk")]
pub use devices::BlockDevice;
#[cfg(feature = "gpu")]
pub use devices::GpuDevice;
#[cfg(feature = "net")]
pub use devices::NetDevice;

pub use devices::{
    AttachContext, AttachDevice, BalloonDevice, ConsoleBuilder, ConsoleDevice, DeviceManager,
    DeviceRequirements, FsDevice, MmioDeviceManager, ResolvedShmRegion, RngDevice, VsockDevice,
};
pub use error::{DetailedError, Error};
pub use init_blob::{Config as InitConfig, ConfigBuilder as InitConfigBuilder, GuestFile};
pub use logging::{init_log, LogLevel, LogStyle, LogTarget};
pub use payload::{FreeBsdKernelFormat, FreeBsdPayload, KrunPayload, Krunfw, Payload};
pub use vmm_builder::{Vmm, VmmBuilder};

ffier::library_definition!("krun", library_tag = 1,
    primitives_prefix = "krun",
    crate::api::error::Error = 1,
    crate::api::devices::MmioDeviceManager<'_> = 2,
    crate::api::devices::FsDevice<'_> = 3,
    crate::api::devices::ConsoleDevice<'_> = 4,
    crate::api::devices::ConsoleBuilder<'_> = 5,
    crate::api::devices::BalloonDevice = 6,
    crate::api::devices::RngDevice = 7,
    crate::api::payload::Krunfw = 8,
    crate::api::payload::Payload for crate::api::payload::Krunfw,
    crate::api::devices::AttachDevice for crate::api::devices::FsDevice,
    crate::api::devices::AttachDevice for crate::api::devices::ConsoleDevice,
    crate::api::devices::AttachDevice for crate::api::devices::BalloonDevice,
    crate::api::devices::AttachDevice for crate::api::devices::RngDevice,
    crate::api::vmm_builder::VmmBuilder<'_> = 10,
    crate::api::vmm_builder::Vmm<'_> = 11,
    trait ffier_builtins::PushStr = 12,
    trait ffier_builtins::Error = 13,
    Error for crate::api::error::Error,
    enum crate::api::logging::LogLevel,
    enum crate::api::logging::LogStyle,
    enum crate::api::logging::LogTarget,
    fn crate::api::logging::init_log,
);

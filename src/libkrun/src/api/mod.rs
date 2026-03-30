pub mod devices;
pub mod error;
pub mod logging;
pub mod payload;
pub mod vmm_builder;

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
pub use logging::{init_log, LogLevel, LogStyle, LogTarget};
pub use payload::{Init, InitBuilder, KrunPayload, Payload};
pub use vmm_builder::{Vmm, VmmBuilder};

ffier::library_definition!("krun",
    crate::api::error::Error = 1,
    crate::api::devices::MmioDeviceManager<'_> = 2,
    crate::api::devices::FsDevice<'_> = 3,
    crate::api::devices::ConsoleDevice<'_> = 4,
    crate::api::devices::ConsoleBuilder<'_> = 5,
    crate::api::devices::BalloonDevice = 6,
    crate::api::devices::RngDevice = 7,
    crate::api::payload::Init = 8,
    crate::api::payload::InitBuilder<'_, '_> = 9,
    crate::api::payload::Payload for crate::api::payload::Init,
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

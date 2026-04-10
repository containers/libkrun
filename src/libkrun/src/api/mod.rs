pub mod devices;
pub mod error;
pub mod payload;
pub mod vmm_builder;

pub use devices::{
    AttachContext, AttachDevice, BalloonDevice, ConsoleBuilder, ConsoleDevice, DeviceManager,
    DeviceRequirements, FsDevice, MmioDeviceManager, ResolvedShmRegion, RngDevice,
};
pub use error::{DetailedError, Error};
pub use payload::{Init, InitBuilder, KrunPayload, Payload};
pub use vmm_builder::{Vmm, VmmBuilder};

ffier::library_definition!("krun",
    Error,
    MmioDeviceManager,
    FsDevice, ConsoleDevice, ConsoleBuilder,
    BalloonDevice, RngDevice,
    Init, InitBuilder,
    Payload for Init,
    AttachDevice for FsDevice,
    AttachDevice for ConsoleDevice,
    AttachDevice for BalloonDevice,
    AttachDevice for RngDevice,
    VmmBuilder, Vmm,
);

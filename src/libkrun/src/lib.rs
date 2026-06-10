pub mod api;
pub use api::*;

// Workaround: `pub mod devices` in api/mod.rs shadows the external `devices`
// crate, so we re-export device internals from crate root where the name
// isn't shadowed.
#[doc(hidden)]
pub mod reexports {
    pub use devices::virtio::TsiFlags;
    #[cfg(feature = "net")]
    pub use devices::virtio::net::device::VirtioNetBackend;
    pub use devices::virtio::port_io;
}

/// Standard virtio-net features for host-guest networking.
#[cfg(feature = "net")]
pub const COMPAT_NET_FEATURES: u32 = (1 << 0)  // CSUM
    | (1 << 1)  // GUEST_CSUM
    | (1 << 7)  // GUEST_TSO4
    | (1 << 10) // GUEST_UFO
    | (1 << 11) // HOST_TSO4
    | (1 << 14); // HOST_UFO

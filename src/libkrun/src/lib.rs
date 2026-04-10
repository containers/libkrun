pub mod api;
pub use api::*;

// Re-export ffier hidden modules from submodules to crate root
// (the bridge macros in the cdylib crate look for $crate::_ffier_<name>)
pub use api::devices::_ffier_balloon_device;
pub use api::devices::_ffier_console_builder;
pub use api::devices::_ffier_console_device;
pub use api::devices::_ffier_fs_device;
pub use api::devices::_ffier_mmio_device_manager;
pub use api::devices::_ffier_rng_device;
pub use api::payload::_ffier_init;
pub use api::payload::_ffier_init_builder;
pub use api::vmm_builder::_ffier_vmm;
pub use api::vmm_builder::_ffier_vmm_builder;

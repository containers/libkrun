pub static INIT_BINARY: &[u8] = include_bytes!(env!("KRUN_INIT_BINARY_PATH"));

pub mod config;
pub use config::{
    Config, ConfigBuilder, ConfigError, GuestFile, INIT_PATH, KERNEL_INIT_ARG, Mount,
};

ffier::library_definition!("krun_init",
    library_tag = 2,
    primitives_prefix = "krun",
    trait ffier_builtins::PushStr = 1,
    trait ffier_builtins::Error = 2,
    crate::config::ConfigError = 3,
    crate::config::GuestFile = 4,
    crate::config::Config = 5,
    crate::config::ConfigBuilder = 6,
);

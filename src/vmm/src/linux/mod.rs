#[cfg(all(feature = "tee", target_arch = "x86_64"))]
pub mod tee;

pub mod vstate;

#[cfg(feature = "amd-sev")]
pub mod amdsev;

#[cfg(feature = "amd-sev")]
pub mod amdsnp;

#[cfg(feature = "intel-tdx")]
pub mod inteltdx;

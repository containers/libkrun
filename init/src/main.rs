mod config;
mod dhcp;
mod env;
mod exec;
mod fs;

fn main() {
    #[cfg(any(feature = "amd-sev", feature = "tdx"))]
    fs::mount_tee_block_device().expect("mount block root failed");
}

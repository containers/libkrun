fn main() {
    #[cfg(target_os = "linux")]
    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,-soname,libkrun.so.{}",
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap()
    );
    #[cfg(target_os = "macos")]
    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,-install_name,libkrun.{}.dylib,-compatibility_version,{}.0.0,-current_version,{}.{}.0",
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap(), std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap(),
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap(), std::env::var("CARGO_PKG_VERSION_MINOR").unwrap()
    );
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=framework=Hypervisor");
    #[cfg(feature = "cca")]
    println!("cargo:rustc-link-lib=krunfw");
}

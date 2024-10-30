fn main() {
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=framework=Hypervisor");
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-search=/usr/local/lib");
    #[cfg(all(not(feature = "tee"), not(feature = "efi")))]
    println!("cargo:rustc-link-lib=krunfw");
    #[cfg(feature = "tee")]
    println!("cargo:rustc-link-lib=krunfw-sev");
}

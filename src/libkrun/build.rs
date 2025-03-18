fn main() {
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=framework=Hypervisor");
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-search=/opt/homebrew/lib");
    #[cfg(all(not(feature = "tee"), not(feature = "efi")))]
    println!("cargo:rustc-link-lib=krunfw");
    #[cfg(all(feature = "tee", target_arch = "x86_64"))]
    println!("cargo:rustc-link-lib=krunfw-sev");
}

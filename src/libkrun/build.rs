fn main() {
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=framework=Hypervisor");
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-search=/opt/homebrew/lib");
    #[cfg(not(feature = "amd-sev"))]
    println!("cargo:rustc-link-lib=krunfw");
    #[cfg(feature = "amd-sev")]
    println!("cargo:rustc-link-lib=krunfw-sev");
    #[cfg(target_arch = "aarch64")]
    println!("cargo:rustc-link-lib=fdt");
}

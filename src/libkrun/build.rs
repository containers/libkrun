fn main() {
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=framework=Hypervisor");
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-search=/opt/homebrew/lib");
    #[cfg(not(feature = "tee"))]
    println!("cargo:rustc-link-lib=krunfw");
    #[cfg(feature = "tee")]
    println!("cargo:rustc-link-lib=krunfw-sev");
}

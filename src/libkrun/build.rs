fn main() {
    println!("cargo:rustc-link-lib=krunfw");
    #[cfg(target_arch = "aarch64")]
    println!("cargo:rustc-link-lib=fdt");
}

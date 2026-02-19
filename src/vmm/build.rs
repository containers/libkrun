fn main() {
    #[cfg(target_arch = "aarch64")]
    {
        let edk2_binary_path = std::env::var("KRUN_EDK2_BINARY_PATH").unwrap_or_else(|_| {
            format!(
                "{}/../../edk2/KRUN_EFI.silent.fd",
                std::env::var("CARGO_MANIFEST_DIR").unwrap()
            )
        });
        println!("cargo:rustc-env=KRUN_EDK2_BINARY_PATH={edk2_binary_path}");
        println!("cargo:rerun-if-changed={edk2_binary_path}");
    }
}

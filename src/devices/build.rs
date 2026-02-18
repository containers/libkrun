fn main() {
    let init_binary_path = std::env::var("KRUN_INIT_BINARY_PATH").unwrap_or_else(|_| {
        format!(
            "{}/../../init/init",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )
    });
    println!("cargo:rustc-env=KRUN_INIT_BINARY_PATH={init_binary_path}");
    println!("cargo:rerun-if-env-changed=KRUN_INIT_BINARY_PATH");
}

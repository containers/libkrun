use std::path::PathBuf;

fn main() {
    let init_binary_path = std::env::var_os("KRUN_INIT_BINARY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
            manifest_dir.join("../../init/init")
        });
    println!(
        "cargo:rustc-env=KRUN_INIT_BINARY_PATH={}",
        init_binary_path.display()
    );
    println!("cargo:rerun-if-env-changed=KRUN_INIT_BINARY_PATH");
}

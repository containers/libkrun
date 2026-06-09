fn main() {
    println!("cargo:rustc-link-lib=dylib=krun_init");

    // If krun-sys already found the library directory via pkg-config,
    // it's on the linker search path. Otherwise, check KRUN_INIT_LIB_PATH.
    if let Ok(path) = std::env::var("KRUN_INIT_LIB_PATH") {
        println!("cargo:rustc-link-search=native={path}");
    }
}

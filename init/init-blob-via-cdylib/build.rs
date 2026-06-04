fn main() {
    if pkg_config::probe_library("libkrun_init").is_err() {
        // Fallback: libkrun_init.so is being built in the same workspace,
        // so pkg-config won't find it yet. Emit the link directive manually;
        // the library will be on the search path at test/install time.
        println!("cargo:rustc-link-lib=dylib=krun_init");
    }
}

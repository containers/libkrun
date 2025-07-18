use std::env;
use std::path::PathBuf;

fn main() -> Result<(), pkg_config::Error> {
    println!("cargo::rerun-if-changed=wrapper.h");

    let library = pkg_config::probe_library("libkrun")?;

    let bindings = bindgen::Builder::default()
        .clang_args(
            library
                .include_paths
                .iter()
                .map(|path| format!("-I{}", path.to_string_lossy())),
        )
        .clang_arg("-fretain-comments-from-system-headers")
        .header("wrapper.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    Ok(())
}

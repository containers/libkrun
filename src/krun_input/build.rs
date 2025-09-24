use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=libkrun_input.h");

    let bindings = bindgen::Builder::default()
        .header("libkrun_input.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("input_header.rs"))
        .expect("Couldn't write bindings!");
}

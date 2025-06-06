use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=libkrun_display.h");

    let bindings = bindgen::Builder::default()
        .header("libkrun_display.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("display_header.rs"))
        .expect("Couldn't write bindings!");
}

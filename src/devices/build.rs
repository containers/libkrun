use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

fn build_default_init() -> PathBuf {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let libkrun_root = manifest_dir.join("../..");
    let init_src = libkrun_root.join("init/init.c");
    let init_bin = libkrun_root.join("init/init");

    println!("cargo:rerun-if-env-changed=CC_LINUX");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=TIMESYNC");
    println!("cargo:rerun-if-changed={}", init_src.display());
    println!(
        "cargo:rerun-if-changed={}",
        libkrun_root.join("init/jsmn.h").display()
    );

    let mut init_cc_flags = vec!["-O2", "-static", "-Wall"];
    if std::env::var_os("TIMESYNC").as_deref() == Some(OsStr::new("1")) {
        init_cc_flags.push("-D__TIMESYNC__");
    }

    let cc_value = std::env::var("CC_LINUX")
        .or_else(|_| std::env::var("CC"))
        .unwrap_or_else(|_| "cc".to_string());
    let mut cc_parts = cc_value.split_ascii_whitespace();
    let cc = cc_parts.next().expect("CC_LINUX/CC must not be empty");
    let status = Command::new(cc)
        .args(cc_parts)
        .args(&init_cc_flags)
        .arg("-o")
        .arg(&init_bin)
        .arg(&init_src)
        .status()
        .unwrap_or_else(|e| panic!("failed to execute {cc}: {e}"));

    if !status.success() {
        panic!("failed to compile init/init.c: {status}");
    }
    init_bin
}

fn main() {
    let init_binary_path = std::env::var_os("KRUN_INIT_BINARY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(build_default_init);
    println!(
        "cargo:rustc-env=KRUN_INIT_BINARY_PATH={}",
        init_binary_path.display()
    );
    println!("cargo:rerun-if-env-changed=KRUN_INIT_BINARY_PATH");
}

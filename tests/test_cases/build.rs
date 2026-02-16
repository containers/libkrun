fn main() {
    println!("cargo:rerun-if-env-changed=IPERF_DURATION");
}

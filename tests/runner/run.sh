#/bin/sh

# self test_cases the testing framework first:
cargo test

# TODO: check for arm, and build arm image instead!
cargo build --target=x86_64-unknown-linux-musl --bin e2e-test-guest --features guest
cargo run --bin e2e-test-host --features "host krun-sys"
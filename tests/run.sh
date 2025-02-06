#/bin/sh

# This script has to be run with the working directory being "test"
# This runs the tests on the libkrun instance found by pkg-config.
# Specify PKG_CONFIG_PATH env variable to test a non-system installation of libkurn.

set -e

# Run the unit tests first (this tests the testing framework itself not libkrun)
cargo test -p test_cases --features guest

GUEST_TARGET_ARCH="$(uname -m)-unknown-linux-musl"

cargo build --target=$GUEST_TARGET_ARCH -p guest-agent
KRUN_TEST_GUEST_AGENT_PATH="target/$GUEST_TARGET_ARCH/debug/guest-agent" cargo run -p runner "$@"

#!/bin/sh

# This script has to be run with the working directory being "test"
# This runs the tests on the libkrun instance found by pkg-config.
# Specify PKG_CONFIG_PATH env variable to test a non-system installation of libkurn.

set -e

# Run the unit tests first (this tests the testing framework itself not libkrun)
cargo test -p test_cases --features guest

GUEST_TARGET_ARCH="$(uname -m)-unknown-linux-musl"

cargo build --target=$GUEST_TARGET_ARCH -p guest-agent
cargo build -p runner

export KRUN_TEST_GUEST_AGENT_PATH="target/$GUEST_TARGET_ARCH/debug/guest-agent"

# Build runner args: pass through all arguments
RUNNER_ARGS="$*"

# Add --base-dir if KRUN_TEST_BASE_DIR is set
if [ -n "${KRUN_TEST_BASE_DIR}" ]; then
	RUNNER_ARGS="${RUNNER_ARGS} --base-dir ${KRUN_TEST_BASE_DIR}"
fi

if [ -z "${KRUN_NO_UNSHARE}" ] && which unshare 2>&1 >/dev/null; then
	unshare --user --map-root-user --net -- /bin/sh -c "ifconfig lo 127.0.0.1 && exec target/debug/runner ${RUNNER_ARGS}"
else
	echo "WARNING: Running tests without a network namespace."
	echo "Tests may fail if the required network ports are already in use."
	echo
	target/debug/runner ${RUNNER_ARGS}
fi

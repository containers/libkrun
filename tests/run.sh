#!/bin/sh

# This script has to be run with the working directory being "test"
# This runs the tests on the libkrun instance found by pkg-config.
# Specify PKG_CONFIG_PATH env variable to test a non-system installation of libkurn.

set -e

OS=$(uname -s)
 # macOS uses the string "arm64" but Rust uses "aarch64"
ARCH=$(uname -m | sed 's/^arm64$/aarch64/') 

GUEST_TARGET="${ARCH}-unknown-linux-musl"

# Run the unit tests first (this tests the testing framework itself not libkrun)
# Only run on Linux - guest code uses Linux-specific ioctls
if [ "$OS" = "Linux" ]; then
	cargo test -p test_cases --features guest
fi

# On macOS, we need to cross-compile for Linux musl
if [ "$OS" = "Darwin" ]; then
	SYSROOT="../linux-sysroot"
	if [ ! -d "$SYSROOT" ]; then
		echo "ERROR: Linux sysroot not found at $SYSROOT"
		echo "Run 'make' in the libkrun root directory first to create it."
		exit 1
	fi

	export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="clang"
	export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-arg=-target -C link-arg=aarch64-linux-gnu -C link-arg=-fuse-ld=lld -C link-arg=--sysroot=$SYSROOT -C link-arg=-static"
	echo "Cross-compiling guest-agent for $GUEST_TARGET"
fi

cargo build --target=$GUEST_TARGET -p guest-agent
cargo build -p runner

# On macOS, the runner needs entitlements to use Hypervisor.framework
if [ "$OS" = "Darwin" ]; then
	codesign --entitlements /dev/stdin --force -s - target/debug/runner <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
EOF
fi

export KRUN_TEST_GUEST_AGENT_PATH="target/$GUEST_TARGET/debug/guest-agent"

# Build runner args: pass through all arguments
RUNNER_ARGS="$*"

# Add --base-dir if KRUN_TEST_BASE_DIR is set
if [ -n "${KRUN_TEST_BASE_DIR}" ]; then
	RUNNER_ARGS="${RUNNER_ARGS} --base-dir ${KRUN_TEST_BASE_DIR}"
fi

# Build rootfs images before entering the network namespace (needs internet + podman)
target/debug/runner build-images

if [ "$OS" != "Darwin" ] && [ -z "${KRUN_NO_UNSHARE}" ] && which unshare 2>&1 >/dev/null; then
	unshare --user --map-root-user --net -- /bin/sh -c "ifconfig lo 127.0.0.1 && exec target/debug/runner ${RUNNER_ARGS}"
else
	echo "WARNING: Running tests without a network namespace."
	echo "Tests may fail if the required network ports are already in use."
	echo
	target/debug/runner ${RUNNER_ARGS}
fi

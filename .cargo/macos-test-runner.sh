#!/bin/sh
# Cargo target runner for macOS (aarch64-apple-darwin).
# Codesigns the test/run binary with the Hypervisor.framework entitlement
# before executing it, so that HVF-based tests can run without a developer
# certificate.
set -eu

BINARY="$1"
shift

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
codesign --entitlements "$REPO_ROOT/hvf-entitlements.plist" --force -s - "$BINARY"
exec "$BINARY" "$@"

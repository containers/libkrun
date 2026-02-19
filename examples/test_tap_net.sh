#!/bin/bash
# Test script for virtio-net with tap backend
# This script builds libkrun, compiles chroot_vm, and runs a network test

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PREFIX="$SCRIPT_DIR/libkrun-prefix"
CHROOT_ROOT="${CHROOT_ROOT:-/home/mhrica/c/my_rootfs2}"
TAP_DEVICE="${TAP_DEVICE:-tap0}"

echo "=== libkrun tap network test ==="
echo "Project root: $PROJECT_ROOT"
echo "Prefix: $PREFIX"
echo "Chroot root: $CHROOT_ROOT"
echo "TAP device: $TAP_DEVICE"
echo ""

# Build and install libkrun
cd "$PROJECT_ROOT"

if [[ "$1" == "--rebuild" ]] || [[ ! -f "$PREFIX/lib64/libkrun.so" ]]; then
    echo "=== Building libkrun ==="
    make clean 2>/dev/null || true
    make PREFIX="$PREFIX"
    make install PREFIX="$PREFIX"
fi

# Compile chroot_vm
echo "=== Compiling chroot_vm_test ==="
cd "$SCRIPT_DIR"
PKG_CONFIG_PATH="$PREFIX/lib64/pkgconfig" \
    gcc -g -o chroot_vm_test chroot_vm.c $(pkg-config --cflags --libs libkrun)

# Create a named pipe for log output
LOG_PIPE="$SCRIPT_DIR/krun_log_pipe"
rm -f "$LOG_PIPE"
mkfifo "$LOG_PIPE"

# Start log reader in background
echo "=== Starting log reader ==="
cat "$LOG_PIPE" &
LOG_PID=$!

# Cleanup on exit
cleanup() {
    kill $LOG_PID 2>/dev/null || true
    rm -f "$LOG_PIPE"
}
trap cleanup EXIT

# Run the test
echo "=== Running chroot_vm with tap backend ==="
echo "Command: LD_LIBRARY_PATH=$PREFIX/lib64 ./chroot_vm_test --color-log=$LOG_PIPE --net=TAP --tap=$TAP_DEVICE $CHROOT_ROOT /usr/bin/ping -c 3 8.8.8.8"
echo ""

LD_LIBRARY_PATH="$PREFIX/lib64" \
    ./chroot_vm_test \
    --color-log="$LOG_PIPE" \
    --net=TAP \
    --tap="$TAP_DEVICE" \
    "$CHROOT_ROOT" \
    /guest_net_test.sh

echo ""
echo "=== Test complete ==="

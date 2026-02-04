# Vectored I/O Net Backend - Claude Notes

## Summary

This branch implements vectored I/O for virtio-net using `RxQueueProducer` and `TxQueueConsumer` abstractions for both TAP and Passt backends.

## IMPORTANT: Queue Cloning Bug

**The virtio `Queue` struct is NOT supposed to be clonable.** The current `Clone` implementation can never work correctly because:

1. When a Queue is cloned, the clone has its own copy of the `next_avail` and `next_used` indices
2. When one clone advances these indices (via `pop()` or `add_used()`), other clones become out of sync
3. The current code relies on only using the **most recent clone** - older clones become stale and unusable

**Current workaround**: The code in `device.rs` does `self.queues.clone()` when activating the device. This works because the cloned queues are passed to the worker thread and the original queues in the device struct are never used again. Many other devices do this same pattern and they work.

**Future fix**: There is a planned PR to fix the Queue interface properly (likely by using shared state or removing Clone).

## Test Status

| Test | Status | Notes |
|------|--------|-------|
| net-tap | PASS | Requires `KRUN_NO_UNSHARE=1` (TAP device already exists on host) |
| net-passt | PASS | Works with default unshare |

## TAP Backend (Working)

### How to Run
```bash
# First, create the TAP device (requires sudo)
sudo ./tests/create_tap.sh

# Run the test without unshare (the tap device already exists on host, not in a new namespace)
KRUN_NO_UNSHARE=1 LIBKRUN_TAP_NAME=tap0 make test NET=1 TEST=net-tap
```

### Key Implementation Details

- **File**: `src/devices/src/virtio/net/tap.rs`
- Uses `writev()` for TX - TAP scatter-gather combines iovecs into a single packet
- Uses `readv()` for RX - scatter-gather read into descriptor chain
- One `writev()`/`readv()` call per Ethernet packet
- Attaches to pre-existing TAP interface via TUNSETIFF

### Why KRUN_NO_UNSHARE=1?

The test runner normally uses `unshare --net` to create an isolated network namespace. However, the TAP device exists in the **host** network namespace. When running in an isolated namespace, TUNSETIFF "succeeds" (returns 0) but doesn't actually attach because the interface doesn't exist in that namespace.

## Passt Backend (Working)

### How to Run
```bash
make test NET=1 TEST=net-passt
```

### Root Cause of Previous Failure

The TX timeout was caused by **missing O_NONBLOCK** on the Unix stream socket. The `Unixstream::new()` constructor was calling `fd.set_nonblocking(true)` but the error wasn't being checked properly. The socket remained blocking, which caused the event loop to stall.

**Fix**: Properly set O_NONBLOCK on the socket using the `SetNonblockingExt` trait.

## Architecture

### TX Path (Guest -> Host)
1. Guest places packet in TX virtqueue (may span multiple descriptors)
2. `TxQueueConsumer::feed()` collects descriptor chains
3. `TxQueueConsumer::consume()` provides frames as `&[IoSliceMut]`
4. Backend calls `writev()` once per frame (packet)

### RX Path (Host -> Guest)
1. `RxQueueProducer::feed()` collects available RX descriptors
2. `RxQueueProducer::produce()` provides chains as `&mut [IoSliceMut]`
3. Backend calls `readv()` to scatter-gather into descriptor chain
4. `Completer::complete()` marks descriptor as used with byte count

## Files Modified

- `src/devices/src/virtio/net/tap.rs` - TAP backend implementation
- `src/devices/src/virtio/net/device.rs` - Device integration
- `tests/test_cases/src/test_net_tap.rs` - TAP test case
- `tests/create_tap.sh` - TAP setup script

# TSI Testing Guide for AI Agents

This guide explains how to run and debug TSI (Transparent Socket Impersonation) tests for libkrun.

## Directory Structure

- **libkrun**: `~/Dev2/libkrun/t/test-fix-tsi` - contains test code and libkrun source
- **libkrunfw**: `~/Dev2/libkrunfw/t/tsi-dgram-fix` - contains kernel patches
- **test-prefix**: `~/Dev2/libkrun/t/test-fix-tsi/test-prefix` - where libraries are installed for testing

## Running Tests

**IMPORTANT: Always use `make test` from the libkrun directory. Do NOT use `./run.sh` directly - the Makefile handles library paths and environment setup correctly.**

### Run all tests
```bash
cd ~/Dev2/libkrun/t/test-fix-tsi
make test
```

### Run a specific test
```bash
cd ~/Dev2/libkrun/t/test-fix-tsi
make test TEST=tsi-unix-dgram-setsockopt
```

### Run with timeout (useful for tests that may hang on kernel panic)
```bash
cd ~/Dev2/libkrun/t/test-fix-tsi
timeout 30 make test TEST=tsi-unix-dgram-setsockopt
```

### Specify custom output directory (recommended for debugging)

Use `--base-dir` to specify where test artifacts are saved. Use a timestamped path to avoid conflicts:

```bash
cd ~/Dev2/libkrun/t/test-fix-tsi
make test TEST=tsi-unix-dgram-setsockopt TEST_FLAGS="--base-dir /tmp/tsi-test-$(date +%Y%m%d-%H%M%S) --keep-all"
```

This creates a predictable output location like `/tmp/tsi-test-20251201-143628/` containing:
- `<test-name>/log.txt` - full test log with kernel output
- `<test-name>/root/` - guest filesystem artifacts

### Keep test artifacts for debugging
```bash
make test TEST=tsi-unix-dgram-setsockopt TEST_FLAGS="--keep-all"
```

Note: Without `--keep-all`, artifacts are only kept for failed tests.

## Switching Kernels

Tests use whatever libkrunfw is installed in `test-prefix/lib64/`.

### Install patched kernel (tsi-dgram-fix branch)
```bash
cd ~/Dev2/libkrunfw/t/tsi-dgram-fix
PREFIX="$(realpath ~/Dev2/libkrun/t/test-fix-tsi/test-prefix)" make install
```

### Install unpatched kernel (main branch) to verify bugs exist
```bash
cd ~/Dev2/libkrunfw/t/main
PREFIX="$(realpath ~/Dev2/libkrun/t/test-fix-tsi/test-prefix)" make install
```

### Safely remove libkrunfw before switching
```bash
rm -f ~/Dev2/libkrun/t/test-fix-tsi/test-prefix/lib64/libkrunfw*
```

## Debugging Kernel Panics

### Viewing kernel output

Filter for kernel messages in the log file:
```bash
grep "init_or_kernel]" /tmp/tsi-test-XXXXXXXX/tsi-unix-dgram-setsockopt/log.txt
```

This shows kernel boot messages and panic traces.

### Enabling verbose kernel output

By default, kernel output is suppressed. To see kernel panics and debug messages, edit:
```
src/vmm/src/vmm_config/kernel_cmdline.rs
```

**Default (quiet, no panic output):**
```rust
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=-1 panic_print=0 nomodule console=hvc0 \
                                          rootfstype=virtiofs rw quiet no-kvmapf";
```

**For debugging (verbose, shows panics):**
```rust
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=-1 nomodule console=hvc0 \
                                          rootfstype=virtiofs rw no-kvmapf";
```

Changes:
- Remove `quiet` - shows all kernel boot messages
- Remove `panic_print=0` - shows full panic information

**Remember to restore the original settings after debugging!**

### Example: Finding a kernel panic

1. Enable verbose kernel output (edit kernel_cmdline.rs as above)
2. Run the test with timeout and custom output dir:
   ```bash
   cd ~/Dev2/libkrun/t/test-fix-tsi
   timeout 30 make test TEST=tsi-unix-dgram-setsockopt TEST_FLAGS="--base-dir /tmp/tsi-test-$(date +%Y%m%d-%H%M%S) --keep-all"
   ```
3. Filter for kernel messages:
   ```bash
   grep "init_or_kernel]" /tmp/tsi-test-XXXXXXXX/tsi-unix-dgram-setsockopt/log.txt
   ```
4. Look for `BUG:`, `Oops:`, `NULL pointer dereference`, `Call Trace:` etc.

### Example kernel panic output
```
[    0.060929] BUG: kernel NULL pointer dereference, address: 0000000000000000
[    0.061037] #PF: supervisor instruction fetch in kernel mode
[    0.061126] #PF: error_code(0x0010) - not-present page
[    0.061239] Oops: Oops: 0010 [#1] PREEMPT SMP NOPTI
[    0.061311] CPU: 0 UID: 0 PID: 318 Comm: guest-agent Not tainted 6.12.44 #1
[    0.061398] RIP: 0010:0x0
[    0.062476] Call Trace:
[    0.062527]  <TASK>
[    0.062561]  ? tsi_dgram_setsockopt+0x6a/0x90
[    0.062644]  ? do_sock_setsockopt+0xaa/0x190
[    0.062736]  ? __sys_setsockopt+0x5d/0xb0
```

This shows a NULL pointer dereference in `tsi_dgram_setsockopt`.

## Test Files

- Test cases: `tests/test_cases/src/`
- Test runner: `tests/runner/src/main.rs`

### Adding a new test

1. Create `tests/test_cases/src/test_<name>.rs`
2. Register in `tests/test_cases/src/lib.rs`:
   ```rust
   mod test_<name>;
   use test_<name>::Test<Name>;

   // In test_cases() function:
   TestCase::new("test-name", Box::new(Test<Name>)),
   ```

## Common Issues

### Test hangs indefinitely
- Usually indicates a kernel panic or deadlock
- Use `timeout` to prevent waiting forever
- Check logs for kernel panic messages

### "cannot open shared object file: libkrun.so.1"
- Always use `make test` which sets up LD_LIBRARY_PATH correctly
- Do NOT run `./run.sh` directly

### Cargo build lock
- If you see "Blocking waiting for file lock on build directory"
- Another cargo process is running, wait for it or kill it

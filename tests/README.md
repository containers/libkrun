# End-to-end tests
The testing framework here allows you to write code to configure libkrun (using the public API) and run some specific code in the guest.

## Running the tests:
The tests can be ran using `make test` (from the main libkrun directory).
You can also run `./run.sh` inside the `test` directory. When using the `./run.sh` script you probably want specify the `PKG_CONFIG_PATH` enviroment variable, otherwise you will be testing the system wide installation of libkrun.

## Running on macOS

### Prerequisites

1. Install required build tools:
   ```bash
   brew install lld xz
   rustup target add aarch64-unknown-linux-musl
   ```

2. Install libkrunfw (required for non-EFI builds). Either via homebrew:
   ```bash
   brew install libkrunfw
   ```

   Or build from source:
   ```bash
   curl -LO https://github.com/containers/libkrunfw/releases/download/v5.2.0/libkrunfw-prebuilt-aarch64.tgz
   tar -xzf libkrunfw-prebuilt-aarch64.tgz
   cd libkrunfw
   make
   sudo make install
   ```

   If installed from source, add `/usr/local/lib` to your library path:
   ```bash
   export DYLD_LIBRARY_PATH="/usr/local/lib:${DYLD_LIBRARY_PATH}"
   ```

   The test harness automatically handles the library path for homebrew installations.

### Running tests

```bash
make test
```

## Adding tests
To add a test you need to add a new rust module in the `test_cases` directory, implement the  required host and guest side methods (see existing tests) and register the test in the `test_cases/src/lib.rs` to be ran.
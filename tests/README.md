# End-to-end tests
The testing framework here allows you to write code to configure libkrun (using the public API) and run some specific code in the guest. 

## Running the tests:
The tests can be ran using `make test` (from the main libkrun directory).
You can also run `./run.sh` inside the `test` directory. When using the `./run.sh` script you probably want specify the `PKG_CONFIG_PATH` enviroment variable, otherwise you will be testing the system wide installation of libkrun. 

## Adding tests
To add a test you need to add a new rust module in the `test_cases` directory, implement the  required host and guest side methods (see existing tests) and register the test in the `test_cases/src/lib.rs` to be ran.
# libkip

libkip aims to be a library to allow other programs to easily gain KVM-based process isolation capabilites.

**WARNING:** This is still in very early development stages, not suitable for production use cases. 

# Building

## Building the "init" binary

```
cd init
make
```

## Building the library

```
cargo build --release
```

# Installing

Eventually this will be automated, but for now it must be done manually.

```
sudo cp include/libkip.h /usr/include
sudo mkdir /usr/share/libkip
sudo cp init/init /usr/share/libkip
sudo cp prebuilts/vmlinux /usr/share/libkip
sudo cp target/release/libkip.so /usr/lib64
```

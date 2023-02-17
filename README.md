# libkrun

```libkrun``` is a dynamic library that allows programs to easily acquire the ability to run processes in a partially isolated environment using [KVM](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt) Virtualization.

It integrates a VMM (Virtual Machine Monitor, the userspace side of an Hypervisor) with the minimum amount of emulated devices required to its purpose, abstracting most of the complexity that comes from Virtual Machine management, offering users a simple C API.

## Possible use cases

* Adding VM-isolation capabilities to an OCI runtime.
* Implementing a lightweight jailer for serverless workloads.
* Bringing additional self-isolation capabilities to conventional services (think of something as simple as ```chroot```, but more powerful).

## Goals and non-goals

### Goals

* Enable other projects to easily gain KVM-based process isolation capabilities.
* Be self-sufficient (no need for calling to an external VMM) and very simple to use.
* Be as small as possible, implementing only the features required to achieve its goals.
* Have the smallest possible footprint in every aspect (RAM consumption, CPU usage and boot time).
* Be compatible with a reasonable amount of workloads.

### Non-goals

* Become a generic VMM.
* Be compatible with all kinds of workloads.

## Variants

This project provides two different variants of the library:

- **libkrun**: Generic variant compatible with all Virtualization-capable systems.
- **libkrun-sev**: Variant including support for AMD SEV (bare SEV and SEV-ES) memory encryption and remote attestation. Requires an SEV-capable CPU.

Each variant generates a dynamic library with a different name (and ```soname```), so both can be installed at the same time in the same system.

## Virtio device support

### All variants

* virtio-console
* virtio-vsock (specialized for TSI, Transparent Socket Impersonation)

### libkrun

* virtio-fs
* virtio-balloon (only free-page reporting)
* virtio-rng

### libkrun-sev

* virtio-block

## Networking

In ```libkrun```, networking is implemented using a novel technique called **Transparent Socket Impersonation**, or **TSI**. This allows the VM to have network connectivity without a virtual interface (hence, ```virtio-net``` is not among the list of supported devices).

This technique supports both outgoing and incoming connections. It's possible for userspace applications running in the VM are able to transparently connect to endpoints outside the VM, and also receive connections from the outside to ports listening inside the VM.

### Limitations

**TSI** only supports impersonating AF_INET SOCK_DGRAM and SOCK_STREAM sockets. This implies it's not possible to communicate outside the VM with raw sockets.

## Building and installing

### Linux (generic variant)

#### Requirements

* [libkrunfw](https://github.com/containers/libkrunfw)
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf

#### Compiling

```
make
```

#### Installing

```
sudo make install
```

### Linux (SEV variant)

#### Requirements

* The SEV variant of [libkrunfw](https://github.com/containers/libkrunfw), which provides a ```libkrunfw-sev.so``` library.
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf
* OpenSSL headers and libraries (package ```openssl-devel``` in Fedora).

#### Compiling

```
make SEV=1
```

#### Installing

```
sudo make SEV=1 install
```

### macOS

#### Requirements

As part of ```libkrun``` building process, it's necessary to produce a Linux ELF binary from [init/init.c](init/init.c). The easiest way to do this is by using a binary version of [krunvm](https://github.com/slp/krunvm) and its dependencies ([libkrunfw](https://github.com/containers/libkrunfw), and ```libkrun``` itself), such as the one available in the [krunvm Homebrew repo](https://github.com/slp/homebrew-krun), and then executing the [build_on_krunvm.sh](build_on_krunvm.sh) script found in this repository.

This will create a lightweight Linux VM using ```krunvm``` with the current working directory mapped inside it, and produce the Linux ELF binary from [init/init.c](init/init.c).

#### Building the library using krunvm

```
./build_on_krunvm.sh
make
```

## Using the library

Despite being written in Rust, this library provides a simple C API defined in [include/libkrun.h](include/libkrun.h)

## Examples

### chroot_vm

This is a simple example providing ```chroot```-like functionality using ```libkrun```.

#### Building chroot_vm

```
cd examples
make
```

#### Running chroot_vm

To be able to ```chroot_vm```, you need first a directory to act as the root filesystem for your isolated program.

Use the ```rootfs``` target to get a rootfs prepared from the Fedora container image (note: you must have [podman](https://podman.io/) installed):

```
make rootfs
```

Now you can use ```chroot_vm``` to run a process within this new root filesystem:

```
./chroot_vm ./rootfs_fedora /bin/sh
```

If the ```libkrun``` and/or ```libkrunfw``` libraries were installed on a path that's not included in your ```/etc/ld.so.conf``` configuration, you may get an error like this one:

```
./chroot_vm: error while loading shared libraries: libkrun.so: cannot open shared object file: No such file or directory
```

To avoid this problem, use the ```LD_LIBRARY_PATH``` environment variable to point to the location where the libraries were installed. For example, if the libraries were installed in ```/usr/local/lib64```, use something like this:

```
LD_LIBRARY_PATH=/usr/local/lib64 ./chroot_vm rootfs/ /bin/sh
```

## Status

```libkrun``` has achieved maturity and starting version ```1.0.0``` the public API is guaranteed to be stable, following [SemVer](https://semver.org/).

### Known users

- [crun](https://github.com/containers/crun): An OCI runtime that can make use of libkrun to run containers with Virtualization-based isolation.
- [krunvm](https://github.com/slp/krunvm): A CLI tool for creating and running microVMs based on OCI images.

## Getting in contact

The main communication channel is the [VirTEE Matrix channel](https://matrix.to/#/#virtee:matrix.org).

## Acknowledgments

```libkrun``` incorporates code from [Firecracker](https://github.com/firecracker-microvm/firecracker), [rust-vmm](https://github.com/rust-vmm/) and [Cloud-Hypervisor](https://github.com/cloud-hypervisor/).

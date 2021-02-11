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
* Provide the best possible performance.

## Device support

### Virtio devices

* virtio-console
* virtio-fs
* virtio-vsock
* virtio-balloon (only free-page reporting)

### Networking

In ```libkrun```, networking is implemented using a novel technique called **socket-to-vsock impersonation**. This allows the VM to have network connectivity without a virtual interface (hence, ```virtio-net``` is not among the list of supported devices).

The current implementation of this technique, found part in this repository and the other part in the kernel patches included with [libkrunfw](https://github.com/containers/libkrunfw) is just a **proof-of-concept**. It's limited to IPv4 TCP and UNIX connections, only supports recv/send operations, and the implementation itself is still quite hacky. We expect this technique to mature within ```libkrun```, so it can be eventually upstreamed into the Linux kernel and other VMMs.

#### DNS resolutions issues

As, by default, ```glibc``` will use UDP for DNS requests, which is not yet supported by the **socket-to-vsock impersonation** technique described above, name resolution will fail with the default configuration. To work around this, you need to add the following line to the ```/etc/resolv.conf``` of the root filesystem servicing the isolated process:

```
options use-vc
```

## Building and installing

### Linux

#### Requirements

* [libkrunfw](https://github.com/containers/libkrunfw)
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)

#### Compiling

```
make
```

#### Installing

```
sudo make install
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

While functional, ```libkrun``` is still in a **very early development stage**.

Our first priority now is **getting feedback from potential users of the library**, to build a Community around it that would **help us set the priorities and shape it** to be useful for them.

## Acknowledgments

```libkrun``` incorporates code from [Firecracker](https://github.com/firecracker-microvm/firecracker), [rust-vmm](https://github.com/rust-vmm/) and [Cloud-Hypervisor](https://github.com/cloud-hypervisor/).

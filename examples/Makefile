ARCH = $(shell uname -m)
OS = $(shell uname -s)
LDFLAGS_x86_64_Linux = -lkrun
LDFLAGS_aarch64_Linux = -lkrun -lfdt
LDFLAGS_arm64_Darwin = -L/opt/homebrew/lib -lkrun -lfdt
CFLAGS_Linux = -O2 -g
CFLAGS_Darwin = -O2 -g -I/opt/homebrew/include
ROOTFS_DISTRO := fedora
ROOTFS_DIR = rootfs_$(ROOTFS_DISTRO)

.PHONY: clean rootfs

ifeq ($(SEV),1)
    EXAMPLES := sev-attest sev-noattest
else
    EXAMPLES := chroot_vm
endif

all: $(EXAMPLES)

chroot_vm: chroot_vm.c
	gcc -o $@ $< $(CFLAGS_$(OS)) $(LDFLAGS_$(ARCH)_$(OS))
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

sev-attest: sev-attest.c
	gcc -o $@ $< $(CFLAGS_$(OS)) $(LDFLAGS_$(ARCH)_$(OS))

sev-noattest: sev-noattest.c
	gcc -o $@ $< $(CFLAGS_$(OS)) $(LDFLAGS_$(ARCH)_$(OS))

# Build the rootfs to be used with chroot_vm.
rootfs:
	mkdir -p $(ROOTFS_DIR)
	podman create --name libkrun_chroot_vm $(ROOTFS_DISTRO)
	podman export libkrun_chroot_vm | tar xpf - -C $(ROOTFS_DIR)
	podman rm libkrun_chroot_vm

clean:
	rm -rf chroot_vm $(ROOTFS_DIR)

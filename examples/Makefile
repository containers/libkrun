ARCH = $(shell uname -m)
OS = $(shell uname -s)
LDFLAGS_x86_64_Linux = -lkrun
LDFLAGS_aarch64_Linux = -lkrun
LDFLAGS_arm64_Darwin = -L/opt/homebrew/lib -lkrun
LDFLAGS_sev = -lkrun-sev
LDFLAGS_efi = -L/opt/homebrew/lib -lkrun-efi
CFLAGS = -O2 -g -I../include
ROOTFS_DISTRO := fedora
ROOTFS_DIR = rootfs_$(ROOTFS_DISTRO)

.PHONY: clean rootfs

EXAMPLES := chroot_vm external_kernel
ifeq ($(SEV),1)
    EXAMPLES := launch-tee
endif
ifeq ($(EFI),1)
    EXAMPLES := boot_efi
endif

all: $(EXAMPLES)

chroot_vm: chroot_vm.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_$(ARCH)_$(OS))
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

launch-tee: launch-tee.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_sev)

boot_efi: boot_efi.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_efi)
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

external_kernel: external_kernel.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_$(ARCH)_$(OS))
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

# Build the rootfs to be used with chroot_vm.
rootfs:
	mkdir -p $(ROOTFS_DIR)
	podman create --name libkrun_chroot_vm $(ROOTFS_DISTRO)
	podman export libkrun_chroot_vm | tar xpf - -C $(ROOTFS_DIR)
	podman rm libkrun_chroot_vm

clean:
	rm -rf chroot_vm $(ROOTFS_DIR) launch-tee boot_efi external_kernel

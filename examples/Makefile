ARCH = $(shell uname -m)
OS = $(shell uname -s)
LDFLAGS_x86_64_Linux = -lkrun
LDFLAGS_aarch64_Linux = -lkrun -lfdt
LDFLAGS_arm64_Darwin = -L/opt/homebrew/lib -lkrun -lfdt
CFLAGS_Linux = -O2 -g
CFLAGS_Darwin = -O2 -g -I/opt/homebrew/include

.PHONY: clean

all: chroot_vm

chroot_vm: chroot_vm.c
	gcc -o $@ $< $(CFLAGS_$(OS)) $(LDFLAGS_$(ARCH)_$(OS))
ifeq ($(OS),Darwin)
	codesign --entitlements chroot_vm.entitlements --force -s - $@
endif

clean:
	rm -f chroot_vm

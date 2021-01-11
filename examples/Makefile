ARCH = $(shell uname -m)
LDFLAGS_x86_64 = -lkrun
LDFLAGS_aarch64 = -lkrun -lfdt
CFLAGS = -O2 -g

.PHONY: clean

all: chroot_vm

chroot_vm: chroot_vm.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS_$(ARCH))

clean:
	rm -f chroot_vm

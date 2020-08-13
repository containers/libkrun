LDFLAGS = -lkrun
CFLAGS = -O2 -g

.PHONY: clean

all: chroot_vm

chroot_vm: chroot_vm.c
	gcc -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f chroot_vm

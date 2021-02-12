LIBRARY_HEADER = include/libkrun.h
INIT_BINARY = init/init

OS = $(shell uname -s)
LIBRARY_RELEASE_Linux = target/release/libkrun.so
LIBRARY_DEBUG_Linux = target/debug/libkrun.so
LIBRARY_RELEASE_Darwin = target/release/libkrun.dylib
LIBRARY_DEBUG_Darwin = target/debug/libkrun.dylib
LIBDIR_Linux = lib64
LIBDIR_Darwin = lib

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

.PHONY: install clean

all: $(LIBRARY_RELEASE_$(OS))

debug: $(LIBRARY_DEBUG_$(OS))

$(INIT_BINARY): init/init.c
	gcc -O2 -static -Wall -o $@ init/init.c

$(LIBRARY_RELEASE_$(OS)): $(INIT_BINARY)
	cargo build --release

$(LIBRARY_DEBUG_$(OS)): $(INIT_BINARY)
	cargo build --debug

install: $(LIBRARY_RELEASE_$(OS))
	install -d $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/
	install -m 755 $(LIBRARY_RELEASE_$(OS)) $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 $(LIBRARY_HEADER) $(DESTDIR)$(PREFIX)/include

clean:
	rm -f $(INIT_BINARY)
	cargo clean

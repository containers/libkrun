LIBRARY_RELEASE = target/release/libkrun.so
LIBRARY_DEBUG = target/debug/libkrun.so
LIBRARY_HEADER = include/libkrun.h
INIT_BINARY = init/init

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

.PHONY: install clean

all: $(LIBRARY_RELEASE)

debug: $(LIBRARY_DEBUG)

$(INIT_BINARY):
	gcc -O2 -static -o $@ init/init.c

$(LIBRARY_RELEASE): $(INIT_BINARY)
	cargo build --release

$(LIBRARY_DEBUG): $(INIT_BINARY)
	cargo build --debug

install: $(LIBRARY_RELEASE)
	install -d $(DESTDIR)$(PREFIX)/lib64/
	install -m 755 $(LIBRARY_RELEASE) $(DESTDIR)$(PREFIX)/lib64/
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 $(LIBRARY_HEADER) $(DESTDIR)$(PREFIX)/include

clean:
	rm -f $(INIT_BINARY)
	cargo clean

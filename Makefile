LIBRARY_HEADER = include/libkrun.h
INIT_BINARY = init/init

ABI_VERSION=1
FULL_VERSION=1.5.0

ifeq ($(SEV),1)
    VARIANT = -sev
    FEATURE_FLAGS := --features amd-sev
    INIT_DEFS := -DSEV=1
endif

ifeq ($(ROSETTA),1)
    INIT_DEFS := -D__ROSETTA__
endif

OS = $(shell uname -s)

KRUN_BINARY_Linux = libkrun$(VARIANT).so.$(FULL_VERSION)
KRUN_SONAME_Linux = libkrun$(VARIANT).so.$(ABI_VERSION)
KRUN_BASE_Linux = libkrun$(VARIANT).so

KRUN_BINARY_Darwin = libkrun.$(FULL_VERSION).dylib
KRUN_SONAME_Darwin = libkrun.$(ABI_VERSION).dylib
KRUN_BASE_Darwin = libkrun.dylib

LIBRARY_RELEASE_Linux = target/release/$(KRUN_BINARY_Linux)
LIBRARY_DEBUG_Linux = target/debug/$(KRUN_BINARY_Linux)
LIBRARY_RELEASE_Darwin = target/release/$(KRUN_BINARY_Darwin)
LIBRARY_DEBUG_Darwin = target/debug/$(KRUN_BINARY_Darwin)

LIBDIR_Linux = lib64
LIBDIR_Darwin = lib

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

.PHONY: install clean

all: $(LIBRARY_RELEASE_$(OS))

debug: $(LIBRARY_DEBUG_$(OS))

$(INIT_BINARY): init/init.c
	gcc -O2 -static -Wall $(INIT_DEFS) -o $@ init/init.c

$(LIBRARY_RELEASE_$(OS)): $(INIT_BINARY)
	cargo build --release $(FEATURE_FLAGS)
ifeq ($(SEV),1)
	mv target/release/libkrun.so target/release/$(KRUN_BASE_$(OS))
endif
ifeq ($(OS),Linux)
	patchelf --set-soname $(KRUN_SONAME_$(OS)) --output $(LIBRARY_RELEASE_$(OS)) target/release/$(KRUN_BASE_$(OS))
else
	cp target/release/$(KRUN_BASE_$(OS)) $(LIBRARY_RELEASE_$(OS))
endif

$(LIBRARY_DEBUG_$(OS)): $(INIT_BINARY)
	cargo build $(FEATURE_FLAGS)
ifeq ($(SEV),1)
	mv target/debug/libkrun.so target/debug/$(KRUN_BASE_$(OS))
endif
ifeq ($(OS),Linux)
	patchelf --set-soname $(KRUN_SONAME_$(OS)) --output $(LIBRARY_DEBUG_$(OS)) target/debug/$(KRUN_BASE_$(OS))
else
	cp target/debug/$(KRUN_BASE_$(OS)) $(LIBRARY_DEBUG_$(OS))
endif

install:
	install -d $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 $(LIBRARY_HEADER) $(DESTDIR)$(PREFIX)/include
	install -m 755 $(LIBRARY_RELEASE_$(OS)) $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/
	cd $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/ ; ln -sf $(KRUN_BINARY_$(OS)) $(KRUN_SONAME_$(OS)) ; ln -sf $(KRUN_SONAME_$(OS)) $(KRUN_BASE_$(OS))

clean:
	rm -f $(INIT_BINARY)
	cargo clean

LIBRARY_HEADER = include/libkrun.h

ABI_VERSION=1
FULL_VERSION=1.12.1

INIT_SRC = init/init.c
KBS_INIT_SRC =	init/tee/kbs/kbs.h		\
		init/tee/kbs/kbs_util.c		\
		init/tee/kbs/kbs_types.c	\
		init/tee/kbs/kbs_curl.c		\
		init/tee/kbs/kbs_crypto.c	\

SNP_INIT_SRC =	init/tee/snp_attest.c		\
		init/tee/snp_attest.h		\
		$(KBS_INIT_SRC)			\

KBS_LD_FLAGS =	-lcurl -lidn2 -lssl -lcrypto -lzstd -lz -lbrotlidec-static \
		-lbrotlicommon-static

BUILD_INIT = 1
INIT_DEFS =
ifeq ($(SEV),1)
    VARIANT = -sev
    FEATURE_FLAGS := --features amd-sev
    INIT_DEFS += -DSEV=1
    INIT_DEFS += $(KBS_LD_FLAGS)
    INIT_SRC += $(SNP_INIT_SRC)
	BUILD_INIT = 0
endif
ifeq ($(GPU),1)
    FEATURE_FLAGS += --features gpu
endif
ifeq ($(VIRGL_RESOURCE_MAP2),1)
	FEATURE_FLAGS += --features virgl_resource_map2
endif
ifeq ($(BLK),1)
    FEATURE_FLAGS += --features blk
endif
ifeq ($(NET),1)
    FEATURE_FLAGS += --features net
endif
ifeq ($(SND),1)
    FEATURE_FLAGS += --features snd
endif
ifeq ($(EFI),1)
	VARIANT = -efi
	FEATURE_FLAGS := --features efi,gpu
	BUILD_INIT = 0
endif

ifeq ($(TIMESYNC),1)
    INIT_DEFS += -D__TIMESYNC__
endif

OS = $(shell uname -s)

KRUN_BINARY_Linux = libkrun$(VARIANT).so.$(FULL_VERSION)
KRUN_SONAME_Linux = libkrun$(VARIANT).so.$(ABI_VERSION)
KRUN_BASE_Linux = libkrun$(VARIANT).so

KRUN_BINARY_Darwin = libkrun$(VARIANT).$(FULL_VERSION).dylib
KRUN_SONAME_Darwin = libkrun$(VARIANT).$(ABI_VERSION).dylib
KRUN_BASE_Darwin = libkrun$(VARIANT).dylib

LIBRARY_RELEASE_Linux = target/release/$(KRUN_BINARY_Linux)
LIBRARY_DEBUG_Linux = target/debug/$(KRUN_BINARY_Linux)
LIBRARY_RELEASE_Darwin = target/release/$(KRUN_BINARY_Darwin)
LIBRARY_DEBUG_Darwin = target/debug/$(KRUN_BINARY_Darwin)

LIBDIR_Linux = lib64
LIBDIR_Darwin = lib

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

.PHONY: install clean test $(LIBRARY_RELEASE_$(OS)) $(LIBRARY_DEBUG_$(OS)) libkrun.pc

all: $(LIBRARY_RELEASE_$(OS)) libkrun.pc

debug: $(LIBRARY_DEBUG_$(OS)) libkrun.pc

ifeq ($(BUILD_INIT),1)
INIT_BINARY = init/init
$(INIT_BINARY): $(INIT_SRC)
	gcc -O2 -static -Wall $(INIT_DEFS) -o $@ $(INIT_SRC) $(INIT_DEFS)
endif

$(LIBRARY_RELEASE_$(OS)): $(INIT_BINARY)
	cargo build --release $(FEATURE_FLAGS)
ifeq ($(SEV),1)
	mv target/release/libkrun.so target/release/$(KRUN_BASE_$(OS))
endif
ifeq ($(OS),Darwin)
ifeq ($(EFI),1)
	install_name_tool -id libkrun-efi.dylib target/release/libkrun.dylib
endif
	mv target/release/libkrun.dylib target/release/$(KRUN_BASE_$(OS))
endif
	cp target/release/$(KRUN_BASE_$(OS)) $(LIBRARY_RELEASE_$(OS))

$(LIBRARY_DEBUG_$(OS)): $(INIT_BINARY)
	cargo build $(FEATURE_FLAGS)
ifeq ($(SEV),1)
	mv target/debug/libkrun.so target/debug/$(KRUN_BASE_$(OS))
endif
	cp target/debug/$(KRUN_BASE_$(OS)) $(LIBRARY_DEBUG_$(OS))

libkrun.pc: libkrun.pc.in Makefile
	rm -f $@ $@-t
	sed -e 's|@prefix@|$(PREFIX)|' \
	    -e 's|@libdir@|$(PREFIX)/$(LIBDIR_$(OS))|' \
	    -e 's|@includedir@|$(PREFIX)/include|' \
	    -e 's|@PACKAGE_NAME@|libkrun|' \
	    -e 's|@PACKAGE_VERSION@|$(FULL_VERSION)|' \
	    libkrun.pc.in > $@-t
	mv $@-t $@

install: libkrun.pc
	install -d $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/
	install -d $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/pkgconfig
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 $(LIBRARY_HEADER) $(DESTDIR)$(PREFIX)/include
	install -m 644 libkrun.pc $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/pkgconfig
	install -m 755 $(LIBRARY_RELEASE_$(OS)) $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/
	cd $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/ ; ln -sf $(KRUN_BINARY_$(OS)) $(KRUN_SONAME_$(OS)) ; ln -sf $(KRUN_SONAME_$(OS)) $(KRUN_BASE_$(OS))

clean:
	rm -f $(INIT_BINARY)
	cargo clean
	rm -rf test-prefix
	cd tests; cargo clean

test: $(LIBRARY_RELEASE_$(OS))
	mkdir -p test-prefix
	PREFIX="$$(realpath test-prefix)" make install
	cd tests; LD_LIBRARY_PATH="$$(realpath ../test-prefix/lib64/)" PKG_CONFIG_PATH="$$(realpath ../test-prefix/lib64/pkgconfig/)" ./run.sh

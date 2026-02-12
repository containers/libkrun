LIBRARY_HEADER = include/libkrun.h
LIBRARY_HEADER_DISPLAY = include/libkrun_display.h
LIBRARY_HEADER_INPUT = include/libkrun_input.h

ABI_VERSION=1
FULL_VERSION=1.17.3

INIT_SRC = init/init.c
KBS_INIT_SRC =	init/tee/kbs/kbs.h		\
		init/tee/kbs/kbs_util.c		\
		init/tee/kbs/kbs_types.c	\
		init/tee/kbs/kbs_curl.c		\
		init/tee/kbs/kbs_crypto.c	\

SNP_INIT_SRC =	init/tee/snp_attest.c		\
		init/tee/snp_attest.h		\
		$(KBS_INIT_SRC)			\

TDX_INIT_SRC = $(KBS_INIT_SRC)
AWS_NITRO_INIT_SRC = \
		init/aws-nitro/include/*        	  	\
        init/aws-nitro/main.c				\
        init/aws-nitro/archive.c				\
        init/aws-nitro/args_reader.c			\
        init/aws-nitro/fs.c				\
        init/aws-nitro/device/include/*			\
		init/aws-nitro/device/app_stdio_output.c	\
		init/aws-nitro/device/device.c              \
		init/aws-nitro/device/net_tap_afvsock.c	\
		init/aws-nitro/device/signal.c		\

KBS_LD_FLAGS =	-lcurl -lidn2 -lssl -lcrypto -lzstd -lz -lbrotlidec-static \
		-lbrotlicommon-static

AWS_NITRO_INIT_LD_FLAGS = -larchive -lnsm

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
ifeq ($(TDX),1)
    VARIANT = -tdx
    FEATURE_FLAGS := --features tdx
    INIT_DEFS += -DTDX=1
    INIT_DEFS += $(KBS_LD_FLAGS)
    INIT_SRC += $(KBS_INIT_SRC)
    BUILD_INIT = 0
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
ifeq ($(EFI),1)
    VARIANT = -efi
    FEATURE_FLAGS := --features efi # EFI Implies blk and net
    BUILD_INIT = 0
endif
ifeq ($(GPU),1)
    FEATURE_FLAGS += --features gpu
endif
ifeq ($(SND),1)
    FEATURE_FLAGS += --features snd
endif
ifeq ($(INPUT),1)
    FEATURE_FLAGS += --features input
endif
ifeq ($(AWS_NITRO),1)
	VARIANT = -awsnitro
	FEATURE_FLAGS := --features aws-nitro,net
	BUILD_INIT = 0
endif

ifeq ($(TIMESYNC),1)
    INIT_DEFS += -D__TIMESYNC__
endif

OS = $(shell uname -s)
ARCH = $(shell uname -m)
DEBIAN_DIST ?= bookworm
ROOTFS_DIR = linux-sysroot

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

.PHONY: install clean test test-prefix $(LIBRARY_RELEASE_$(OS)) $(LIBRARY_DEBUG_$(OS)) libkrun.pc clean-sysroot clean-all

all: $(LIBRARY_RELEASE_$(OS)) libkrun.pc

debug: $(LIBRARY_DEBUG_$(OS)) libkrun.pc

ifeq ($(OS),Darwin)
# If SYSROOT_LINUX is not set and we're on macOS, generate sysroot automatically
ifeq ($(SYSROOT_LINUX),)
    SYSROOT_LINUX = $(ROOTFS_DIR)
    SYSROOT_TARGET = $(ROOTFS_DIR)/.sysroot_ready
else
    SYSROOT_TARGET =
endif
    # Cross-compile on macOS with the LLVM linker (brew install lld)
    CC_LINUX=/usr/bin/clang -target $(ARCH)-linux-gnu -fuse-ld=lld -Wl,-strip-debug --sysroot $(SYSROOT_LINUX) -Wno-c23-extensions
else
    # Build on Linux host
    CC_LINUX=$(CC)
    SYSROOT_TARGET =
endif

ifeq ($(BUILD_INIT),1)
INIT_BINARY = init/init
$(INIT_BINARY): $(INIT_SRC) $(SYSROOT_TARGET)
	$(CC_LINUX) -O2 -static -Wall $(INIT_DEFS) -o $@ $(INIT_SRC) $(INIT_DEFS)
endif

AWS_NITRO_INIT_BINARY= init/aws-nitro/init
$(AWS_NITRO_INIT_BINARY): $(AWS_NITRO_INIT_SRC)
	$(CC) -O2 -static -s -Wall $(AWS_NITRO_INIT_LD_FLAGS) -o $@ $(AWS_NITRO_INIT_SRC) $(AWS_NITRO_INIT_LD_FLAGS)

# Sysroot preparation rules for cross-compilation on macOS
DEBIAN_PACKAGES = libc6 libc6-dev libgcc-12-dev linux-libc-dev
ROOTFS_TMP = $(ROOTFS_DIR)/.tmp
PACKAGES_FILE = $(ROOTFS_TMP)/Packages.xz

.INTERMEDIATE: $(PACKAGES_FILE)

$(ROOTFS_DIR)/.sysroot_ready: $(PACKAGES_FILE)
	@echo "Extracting Debian packages to $(ROOTFS_DIR)..."
	@for pkg in $(DEBIAN_PACKAGES); do \
		DEB_PATH=$$(xzcat $(PACKAGES_FILE) | sed '1,/Package: '$$pkg'$$/d' | grep Filename: | sed 's/^Filename: //' | head -n1); \
		DEB_URL="https://deb.debian.org/debian/$$DEB_PATH"; \
		DEB_NAME=$$(basename "$$DEB_PATH"); \
		if [ ! -f "$(ROOTFS_TMP)/$$DEB_NAME" ]; then \
			echo "Downloading $$DEB_URL"; \
			curl -fL -o "$(ROOTFS_TMP)/$$DEB_NAME" "$$DEB_URL"; \
		fi; \
		cd $(ROOTFS_TMP) && ar x "$$DEB_NAME" && cd ../..; \
		tar xf $(ROOTFS_TMP)/data.tar.* -C $(ROOTFS_DIR); \
		rm -f $(ROOTFS_TMP)/*.deb $(ROOTFS_TMP)/data.tar.* $(ROOTFS_TMP)/control.tar.* $(ROOTFS_TMP)/debian-binary; \
	done
	@touch $@

$(PACKAGES_FILE):
	@echo "Downloading Debian package index for $(DEBIAN_DIST)/$(ARCH)..."
	@mkdir -p $(ROOTFS_TMP)
	@curl -fL -o $@ https://deb.debian.org/debian/dists/$(DEBIAN_DIST)/main/binary-$(ARCH)/Packages.xz

clean-sysroot:
	rm -rf $(ROOTFS_DIR)


$(LIBRARY_RELEASE_$(OS)): $(INIT_BINARY)
	cargo build --release $(FEATURE_FLAGS)
ifeq ($(SEV),1)
	mv target/release/libkrun.so target/release/$(KRUN_BASE_$(OS))
endif
ifeq ($(AWS_NITRO),1)
	mv target/release/libkrun.so target/release/$(KRUN_BASE_$(OS))
endif
ifeq ($(TDX),1)
	mv target/release/libkrun.so target/release/$(KRUN_BASE_$(OS))
endif
ifeq ($(OS),Darwin)
ifeq ($(EFI),1)
	install_name_tool -id $(PREFIX)/$(LIBDIR_$(OS))/$(KRUN_SONAME_$(OS)) target/release/libkrun.dylib
endif
	mv target/release/libkrun.dylib target/release/$(KRUN_BASE_$(OS))
endif
	cp target/release/$(KRUN_BASE_$(OS)) $(LIBRARY_RELEASE_$(OS))

$(LIBRARY_DEBUG_$(OS)): $(INIT_BINARY)
	cargo build $(FEATURE_FLAGS)
ifeq ($(SEV),1)
	mv target/debug/libkrun.so target/debug/$(KRUN_BASE_$(OS))
endif
ifeq ($(TDX),1)
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
	install -m 644 $(LIBRARY_HEADER_DISPLAY) $(DESTDIR)$(PREFIX)/include
	install -m 644 $(LIBRARY_HEADER_INPUT) $(DESTDIR)$(PREFIX)/include
	install -m 644 libkrun.pc $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/pkgconfig
	install -m 755 $(LIBRARY_RELEASE_$(OS)) $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/
	cd $(DESTDIR)$(PREFIX)/$(LIBDIR_$(OS))/ ; ln -sf $(KRUN_BINARY_$(OS)) $(KRUN_SONAME_$(OS)) ; ln -sf $(KRUN_SONAME_$(OS)) $(KRUN_BASE_$(OS))

clean:
	rm -f $(INIT_BINARY)
	cargo clean
	rm -rf test-prefix
	cd tests; cargo clean

clean-all: clean clean-sysroot

test-prefix/lib64/libkrun.pc: $(LIBRARY_RELEASE_$(OS))
	mkdir -p test-prefix
	PREFIX="$$(realpath test-prefix)" make install

test-prefix: test-prefix/lib64/libkrun.pc

TEST ?= all
TEST_FLAGS ?=

test: test-prefix
	cd tests; RUST_LOG=trace LD_LIBRARY_PATH="$$(realpath ../test-prefix/lib64/)" PKG_CONFIG_PATH="$$(realpath ../test-prefix/lib64/pkgconfig/)" ./run.sh test --test-case "$(TEST)" $(TEST_FLAGS)

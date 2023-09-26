# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
RUTABAGA_TEST = rutabaga_test
SOURCES += rutabaga_test.c
OBJS = $(SOURCES:.c=.o)
DEPS = $(SOURCES:.c=.d)
PKG_CONFIG ?= pkg-config
CFLAGS += -O0 -ggdb3
CCFLAGS += $(shell $(PKG_CONFIG) --cflags rutabaga_gfx_ffi)
LDLIBS += $(PC_LIBS)
LDLIBS += $(shell $(PKG_CONFIG) --libs rutabaga_gfx_ffi)
.PHONY: all clean
all: $(RUTABAGA_TEST)
$(RUTABAGA_TEST): $(OBJS)
clean:
	$(RM) $(RUTABAGA_TEST)
	$(RM) $(OBJS) $(DEPS)
	$(RM) *.o *.d .version
$(RUTABAGA_TEST):
	$(CC) $(CCFLAGS) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)
$(OBJS): %.o: %.c
	$(CC) $(CCFLAGS) $(CFLAGS) -c $< -o $@ -MMD
-include $(DEPS)

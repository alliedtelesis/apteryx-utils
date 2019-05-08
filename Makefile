# Makefile for Apteryx
#
# Unit Tests (make test FILTER): e.g make test Alfred
# Requires GLib, Lua and libXML2. CUnit for Unit Testing.
# sudo apt-get install libglib2.0-dev liblua5.2-dev libxml2-dev libcunit1-dev
#
# TEST_WRAPPER="G_SLICE=always-malloc valgrind --leak-check=full" make test
# TEST_WRAPPER="gdb" make test
#

ifneq ($(V),1)
	Q=@
endif

DESTDIR?=./
PREFIX?=/usr/
CC:=$(CROSS_COMPILE)gcc
LD:=$(CROSS_COMPILE)ld
PKG_CONFIG ?= pkg-config
APTERYX_PATH ?=
APTERYX_XML_PATH ?=

CFLAGS := $(CFLAGS) -g -O2
EXTRA_CFLAGS += -Wall -Wno-comment -std=c99 -D_GNU_SOURCE -fPIC
EXTRA_CFLAGS += -I. $(shell $(PKG_CONFIG) --cflags glib-2.0)
EXTRA_LDFLAGS += $(shell $(PKG_CONFIG) --libs glib-2.0) -lpthread
ifndef APTERYX_PATH
EXTRA_CFLAGS += $(shell $(PKG_CONFIG) --cflags apteryx)
EXTRA_LDFLAGS += $(shell $(PKG_CONFIG) --libs apteryx)
else
EXTRA_CFLAGS += -I$(APTERYX_PATH)
EXTRA_LDFLAGS += -L$(APTERYX_PATH) -lapteryx
endif
ifdef APTERYX_XML_PATH
EXTRA_CFLAGS += -I$(APTERYX_XML_PATH)
EXTRA_LDFLAGS += -L$(APTERYX_XML_PATH)
endif
LUAVERSION := $(shell $(PKG_CONFIG) --exists lua && echo lua || ($(PKG_CONFIG) --exists lua5.2 && echo lua5.2 || echo none))
EXTRA_CFLAGS += -DHAVE_LUA $(shell $(PKG_CONFIG) --cflags $(LUAVERSION))
EXTRA_LDFLAGS += $(shell $(PKG_CONFIG) --libs $(LUAVERSION)) -ldl
EXTRA_CFLAGS += -DHAVE_LIBXML2 $(shell $(PKG_CONFIG) --cflags libxml-2.0)
EXTRA_LDFLAGS += $(shell $(PKG_CONFIG) --libs libxml-2.0)
ifneq ($(HAVE_TESTS),no)
EXTRA_CSRC += test.c
EXTRA_CFLAGS += -DTEST
EXTRA_LDFLAGS += -lcunit
endif

all: alfred apteryx-sync apteryx-saver

%.o: %.c
	@echo "Compiling "$<""
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

apteryx-saver: saver.o
	@echo "Building $@"
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ $(EXTRA_LDFLAGS) -lapteryx-schema

apteryx-sync: syncer.c
	@echo "Building $@"
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $< $(EXTRA_LDFLAGS)

alfred: alfred.c callbacks.c
	@echo "Building $@"
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ $(EXTRA_LDFLAGS)

apteryxd = \
	if test -e /tmp/apteryxd.pid; then \
		kill -TERM `cat /tmp/apteryxd.pid` && sleep 0.1; \
	fi; \
	rm -f /tmp/apteryxd.pid; \
	rm -f /tmp/apteryxd.run; \
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./ $(APTERYX_PATH)apteryxd -b -p /tmp/apteryxd.pid -r /tmp/apteryxd.run && sleep 0.1; \
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./ $(TEST_WRAPPER) ./$(1); \
	kill -TERM `cat /tmp/apteryxd.pid`;

ifeq (test,$(firstword $(MAKECMDGOALS)))
TEST_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
$(eval $(TEST_ARGS):;@:)
endif

test: alfred
	@echo "Running unit test: $<"
	$(Q)$(call apteryxd,alfred -u$(TEST_ARGS))
	$(Q)rm -f alfred_test.xml alfred_test.lua
	@echo "Tests have been run!"

install: all
	@install -d $(DESTDIR)/$(PREFIX)/bin
	@install -D apteryx-sync $(DESTDIR)/$(PREFIX)/bin/
	@install -D alfred $(DESTDIR)/$(PREFIX)/bin/
	@install -D apteryx-saver $(DESTDIR)/$(PREFIX)/bin/
	@install -d $(DESTDIR)/$(PREFIX)/include
	@install -D apteryx_sync.h $(DESTDIR)/$(PREFIX)/include/

clean:
	@echo "Cleaning..."
	$(Q)rm -f apteryx-sync alfred saver *.o

.PHONY: all clean

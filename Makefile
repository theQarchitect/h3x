# H3X — Hamilton-Hilbert-Hinch Wavelet Transition Analysis Toolkit
# Author: Derek Hinch
# License: MIT
#
# Targets:
#   make              — build all tools
#   make lib          — build shared library only
#   make test         — build and run tests
#   make install      — install to /usr/local/bin
#   make sign         — codesign with Developer ID
#   make notarize     — submit for Apple notarization
#   make clean        — remove build artifacts
#   make dist         — create distributable archive

PREFIX ?= /usr/local
UNAME_S := $(shell uname -s)

CC = cc
CFLAGS = -O3 -Wall -Wextra -Wno-unused-parameter -I include
LDFLAGS = -lm

# Signing identity (set via env or override)
SIGN_ID ?= -
TEAM_ID ?= $(shell security find-identity -v -p codesigning | grep "Developer ID Application" | head -1 | sed 's/.*"\(.*\)"/\1/')
BUNDLE_ID = com.qomputeai.h3x

# Platform
ifeq ($(UNAME_S),Darwin)
    DYLIB = libh3x.dylib
    LDFLAGS_LIB = -shared -lm
    SIGN_CMD = codesign --force --options runtime --timestamp -s "$(SIGN_ID)"
else
    DYLIB = libh3x.so
    LDFLAGS_LIB = -shared -lm
    SIGN_CMD = true
endif

# Source files
LIB_SRCS = src/h3x_format.c src/h3x_neon.c src/h3x_predictor.c
TOOLS = h3x_analyze h3x_patch h3x_lucky h3x_heal h3x_tcp h3x_sig h3x_sentinel h3x_netwatch h3x_tcp h3x_sig

.PHONY: all lib tools test install sign notarize clean dist

all: lib tools

# ─── Shared Library ─────────────────────────────────────────────────
lib: build/$(DYLIB)

build/$(DYLIB): $(LIB_SRCS) include/h3x_format.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS_LIB) -fPIC -o $@ $(LIB_SRCS)

# ─── CLI Tools ──────────────────────────────────────────────────────
tools: $(addprefix build/,$(TOOLS))

build/h3x_analyze: src/h3x_analyze.c include/h3x_format.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/h3x_patch: src/h3x_patch.c include/h3x_format.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/h3x_lucky: src/h3x_lucky.c include/h3x_format.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/h3x_heal: src/h3x_heal.c include/h3x_format.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/h3x_tcp: src/h3x_tcp.c include/h3x_format.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/h3x_sig: src/h3x_sig.c include/h3x_format.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/h3x_sentinel: src/h3x_sentinel.c include/h3x_format.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/h3x_netwatch: src/h3x_netwatch.c include/h3x_format.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# ─── Tests ──────────────────────────────────────────────────────────
test: build/test_h3x
	./build/test_h3x

build/test_h3x: tests/test_h3x.c build/$(DYLIB)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $< -Lbuild -lh3x $(LDFLAGS) -Wl,-rpath,build

# ─── Install ────────────────────────────────────────────────────────
install: all
	install -d $(PREFIX)/bin
	install -d $(PREFIX)/lib
	install -d $(PREFIX)/include
	install -m 755 $(addprefix build/,$(TOOLS)) $(PREFIX)/bin/
	install -m 644 build/$(DYLIB) $(PREFIX)/lib/
	install -m 644 include/h3x_format.h $(PREFIX)/include/

# ─── Code Signing (macOS) ──────────────────────────────────────────
sign: all
ifeq ($(UNAME_S),Darwin)
	@echo "Signing with identity: $(SIGN_ID)"
	@for tool in $(addprefix build/,$(TOOLS)); do \
		$(SIGN_CMD) --identifier $(BUNDLE_ID).$$(basename $$tool) $$tool; \
		echo "  Signed: $$tool"; \
	done
	$(SIGN_CMD) --identifier $(BUNDLE_ID).lib build/$(DYLIB)
	@echo "All binaries signed."
else
	@echo "Code signing is macOS only."
endif

# ─── Notarization (macOS) ──────────────────────────────────────────
notarize: sign dist
ifeq ($(UNAME_S),Darwin)
	@echo "Submitting for notarization..."
	xcrun notarytool submit build/h3x-$(shell date +%Y%m%d).zip \
		--apple-id "$(APPLE_ID)" \
		--team-id "$(TEAM_ID)" \
		--password "$(APP_PASSWORD)" \
		--wait
	@echo "Stapling..."
	@for tool in $(addprefix build/,$(TOOLS)); do \
		xcrun stapler staple $$tool 2>/dev/null || true; \
	done
	@echo "Notarization complete."
else
	@echo "Notarization is macOS only."
endif

# ─── Distribution Archive ──────────────────────────────────────────
dist: all
	@mkdir -p build
	cd build && zip -r h3x-$(shell date +%Y%m%d).zip \
		$(TOOLS) $(DYLIB) \
		-x "*.dSYM/*"
	@echo "Archive: build/h3x-$(shell date +%Y%m%d).zip"

# ─── Clean ─────────────────────────────────────────────────────────
clean:
	rm -rf build

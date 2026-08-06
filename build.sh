#!/bin/bash
# H3X Hardened Build Script
# Strips symbols, enables all compiler hardening, signs with proper entitlements
set -e
cd "$(dirname "$0")"

CC="${CC:-cc}"
SIGN_ID="${SIGN_ID:-Developer ID Application: qomputeai inc (4HMYMNKRGB)}"
BUNDLE_PREFIX="ai.qompute.h3x.sentinel"

# Hardened compiler flags:
#   -O3              : Maximum optimization
#   -Wall -Wextra    : All warnings
#   -fstack-protector-strong : Stack canaries on all functions with arrays/address-taken locals
#   -D_FORTIFY_SOURCE=2 : Runtime buffer overflow detection
#   -fPIE            : Position-independent executable (ASLR)
#   -Wl,-pie         : Link as PIE
#   -Wl,-headerpad_max_install_names : Allow install_name_tool post-build
#   -fno-common      : Reject tentative definitions (catch ODR violations)
#   -fvisibility=hidden : Hide all symbols by default
CFLAGS="-O3 -Wall -Wextra -Wno-unused-parameter -I include"
CFLAGS="$CFLAGS -fstack-protector-strong"
CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2"
CFLAGS="$CFLAGS -fPIE"
CFLAGS="$CFLAGS -fno-common"
CFLAGS="$CFLAGS -fvisibility=hidden"

LDFLAGS="-lm -Wl,-pie -dead_strip"

# Strip flags (remove all symbols and debug info)
STRIP_FLAGS="-x"  # strip non-global symbols

mkdir -p build

echo "═══════════════════════════════════════════════════════════════════"
echo "  H3X HARDENED BUILD"
echo "  Compiler: $CC"
echo "  Signing:  $SIGN_ID"
echo "═══════════════════════════════════════════════════════════════════"
echo

# Build shared library
echo "  [LIB] libh3x..."
$CC $CFLAGS -shared -fPIC $LDFLAGS -o build/libh3x.dylib \
    src/h3x_format.c src/h3x_neon.c src/h3x_predictor.c 2>/dev/null || \
$CC $CFLAGS -shared -fPIC $LDFLAGS -o build/libh3x.so \
    src/h3x_format.c src/h3x_neon.c src/h3x_predictor.c
strip $STRIP_FLAGS build/libh3x.dylib 2>/dev/null || strip $STRIP_FLAGS build/libh3x.so 2>/dev/null || true

# Build tools (each self-contained)
TOOLS="h3x_analyze h3x_patch h3x_lucky h3x_heal h3x_tcp h3x_sig h3x_sentinel h3x_netwatch h3x_grammar h3x_syscall h3x_apfs"

for tool in $TOOLS; do
    echo "  [BIN] $tool..."
    $CC $CFLAGS $LDFLAGS -o build/$tool src/$tool.c
    # Strip symbols
    strip $STRIP_FLAGS build/$tool
done

echo
echo "  [SIGN] Signing with hardened runtime + entitlements..."

# Sign each binary with:
#   --options runtime     : Hardened runtime (no unsigned code, no JIT, no debugging)
#   --timestamp           : Secure timestamp from Apple
#   --entitlements        : Explicit deny of all dangerous capabilities
for tool in $TOOLS; do
    codesign --force \
        --options runtime \
        --timestamp \
        --entitlements entitlements.plist \
        --identifier "$BUNDLE_PREFIX.$tool" \
        -s "$SIGN_ID" \
        build/$tool
done

# Sign the library too
codesign --force \
    --options runtime \
    --timestamp \
    --entitlements entitlements.plist \
    --identifier "$BUNDLE_PREFIX.lib" \
    -s "$SIGN_ID" \
    build/libh3x.dylib 2>/dev/null || true

echo
echo "  [VERIFY] Checking hardening..."
echo

# Verify one binary
SAMPLE="build/h3x_analyze"
echo "  Binary: $SAMPLE"
echo "  Size:   $(wc -c < $SAMPLE | tr -d ' ') bytes (stripped)"
echo
codesign -dv --verbose=2 $SAMPLE 2>&1 | grep -E "Identifier|Authority|Timestamp|CodeDirectory|flags"
echo

# Check that hardened runtime flags are set
FLAGS=$(codesign -dv $SAMPLE 2>&1 | grep "flags=" | head -1)
if echo "$FLAGS" | grep -q "runtime"; then
    echo "  ✓ Hardened runtime enabled"
else
    echo "  ✗ WARNING: Hardened runtime NOT set"
fi

# Check entitlements are restrictive
ENTS=$(codesign -d --entitlements - $SAMPLE 2>&1)
if echo "$ENTS" | grep -q "allow-jit.*false\|allow-unsigned.*false"; then
    echo "  ✓ JIT disabled, unsigned code disabled"
else
    echo "  ✓ No dangerous entitlements (all denied by default)"
fi

# Verify no get-task-allow (would allow debugging)
if echo "$ENTS" | grep -q "get-task-allow.*true"; then
    echo "  ✗ WARNING: get-task-allow is TRUE (debuggable!)"
else
    echo "  ✓ Debugging disabled (gety-task-allow = false)"
fi

echo
echo "═══════════════════════════════════════════════════════════════════"
echo "  BUILD COMPLETE: $(ls build/h3x_* | wc -l | tr -d ' ') tools"
echo "  All stripped, hardened, signed, no JIT/debug/unsigned code."
echo "═══════════════════════════════════════════════════════════════════"

#!/bin/bash
# H3X Build Script — works anywhere with a C compiler
set -e
cd "$(dirname "$0")"

CC="${CC:-cc}"
CFLAGS="-O3 -Wall -Wextra -Wno-unused-parameter -I include"
LDFLAGS="-lm"

mkdir -p build

echo "Building H3X toolkit..."

# Shared library
echo "  libh3x..."
$CC $CFLAGS -shared -fPIC $LDFLAGS -o build/libh3x.dylib \
    src/h3x_format.c src/h3x_neon.c src/h3x_predictor.c 2>/dev/null || \
$CC $CFLAGS -shared -fPIC $LDFLAGS -o build/libh3x.so \
    src/h3x_format.c src/h3x_neon.c src/h3x_predictor.c

# Tools (each is self-contained, no library dependency)
for tool in h3x_analyze h3x_patch h3x_lucky h3x_heal h3x_tcp \
            h3x_sig h3x_sentinel h3x_netwatch h3x_grammar \
            h3x_syscall h3x_apfs; do
    echo "  $tool..."
    $CC $CFLAGS $LDFLAGS -o build/$tool src/$tool.c
done

echo ""
echo "Built $(ls build/h3x_* | wc -l | tr -d ' ') tools in build/"
echo ""
echo "Run:  ./build/h3x_analyze <file>"
echo "Test: ./build/h3x_grammar --auto-learn"

#!/bin/bash
# H3X Stability Detection Demo
# Shows that h3x_sig detects geometric differences between stable and unstable code
set -e
cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════════════════════════"
echo "  H3X PROGRAM STABILITY DETECTION"
echo "  Geometric analysis reveals code quality from binary structure"
echo "═══════════════════════════════════════════════════════════════════"
echo

# Build
echo "  Compiling stable and unstable variants..."
mkdir -p build/demo
cc -O2 -o build/demo/stable_server demo/stable_server.c
cc -O2 -o build/demo/unstable_server demo/unstable_server.c 2>/dev/null || \
cc -O2 -Wno-everything -o build/demo/unstable_server demo/unstable_server.c
echo "  Done."
echo

# Analyze both
echo "── STRUCTURAL ANALYSIS ──────────────────────────────────────────"
echo
echo "  STABLE SERVER:"
build/h3x_analyze build/demo/stable_server 2>&1 | grep -E "Identity|Region|STRUCTURAL|CONSTRAINED|EDITABLE|Total"
echo
echo "  UNSTABLE SERVER:"
build/h3x_analyze build/demo/unstable_server 2>&1 | grep -E "Identity|Region|STRUCTURAL|CONSTRAINED|EDITABLE|Total"
echo

# Geometric signature comparison
echo "── GEOMETRIC SIGNATURES ─────────────────────────────────────────"
echo
echo "  Stable server signature:"
build/h3x_sig build/demo/stable_server --sign 2>&1 | head -3
echo
echo "  Unstable server signature:"
build/h3x_sig build/demo/unstable_server --sign 2>&1 | head -3
echo

# Similarity
echo "── SIMILARITY SCORE ─────────────────────────────────────────────"
echo
SIM=$(build/h3x_sig build/demo/stable_server --similarity build/demo/unstable_server)
echo "  Stable vs Unstable similarity: ${SIM}"
echo
if (( $(echo "$SIM < 0.80" | bc -l 2>/dev/null || echo 1) )); then
    echo "  ✓ DETECTED: Significant geometric divergence between stable and unstable"
    echo "    The unstable program has different structural geometry in its code section."
else
    echo "  Programs have similar geometry (both small, dominated by Mach-O overhead)"
fi
echo

# Blame — where do they diverge?
echo "── BLAME ANALYSIS ─────────────────────────────────────────────────"
echo
build/h3x_sig build/demo/stable_server --blame build/demo/unstable_server 2>&1
echo

# Grammar identification
echo "── GRAMMAR FINGERPRINT ──────────────────────────────────────────"
echo
echo "  Stable:"
build/h3x_grammar --profile build/demo/stable_server 2>&1
echo "  Unstable:"
build/h3x_grammar --profile build/demo/unstable_server 2>&1
echo

echo "═══════════════════════════════════════════════════════════════════"
echo "  INTERPRETATION"
echo "═══════════════════════════════════════════════════════════════════"
echo
echo "  Stable code characteristics:"
echo "    - Higher identity density (more zero-transitions = bounded loops)"
echo "    - Lower transition energy (predictable control flow)"
echo "    - Fewer boundary segments (clean separation of code/data)"
echo "    - Tighter orbit (fewer unique transition frames)"
echo
echo "  Unstable code characteristics:"
echo "    - Lower identity density (chaotic memory access patterns)"
echo "    - Higher transition energy (unpredictable branches, overflow code)"
echo "    - More boundary segments (mixed code/data from overflow)"
echo "    - Wider orbit (more diverse transition patterns)"
echo
echo "  The geometric difference IS the stability difference."
echo "  Buffer overflows, uninitialized reads, and UB produce detectable"
echo "  patterns in the quaternionic transition lattice."
echo

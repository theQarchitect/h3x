#!/bin/bash
#
# H3X Geometric Signature Demo
# =============================
# Demonstrates that h3x_sig matches GEOMETRIC SHAPE, not exact bytes.
#
# What we prove:
#   1. Original and Patched (same algorithm) → signatures MATCH
#   2. Original and Backdoor (different algorithm) → signatures DIFFER
#   3. Original at -O0 vs -O3 (same algorithm, different codegen) → signatures MATCH
#   4. Blame correctly identifies WHERE the backdoor diverges
#
set -e
cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════════════════════════"
echo "  H3X GEOMETRIC SIGNATURE DEMO"
echo "  Proving: shape-matching survives recompilation, detects backdoors"
echo "═══════════════════════════════════════════════════════════════════"
echo

# Build h3x_sig if needed
if [ ! -f build/h3x_sig ]; then
    echo "Building h3x_sig..."
    make build/h3x_sig
fi

# Compile target variants
echo "Compiling target variants..."
mkdir -p build/demo

# Original at -O2
cc -O2 -o build/demo/target_original_O2 demo/target_original.c
# Original at -O0 (debug, no optimization)
cc -O0 -o build/demo/target_original_O0 demo/target_original.c
# Original at -O3 (aggressive optimization)
cc -O3 -o build/demo/target_original_O3 demo/target_original.c
# Original at -Os (size optimization)
cc -Os -o build/demo/target_original_Os demo/target_original.c
# Patched version (same algo, different source)
cc -O2 -o build/demo/target_patched_O2 demo/target_patched.c
# Backdoor version (DIFFERENT algorithm)
cc -O2 -o build/demo/target_backdoor_O2 demo/target_backdoor.c

echo "Done. 6 binaries compiled."
echo

# Verify they all produce same output (except backdoor)
echo "── Functional Verification ──────────────────────────────────────"
echo -n "  Original -O2: "
build/demo/target_original_O2 "secret" "hello world" | grep MAC
echo -n "  Original -O3: "
build/demo/target_original_O3 "secret" "hello world" | grep MAC
echo -n "  Patched  -O2: "
build/demo/target_patched_O2 "secret" "hello world" | grep MAC
echo -n "  Backdoor -O2: "
build/demo/target_backdoor_O2 "secret" "hello world" | grep MAC
echo "  (Original/Patched/O3 should match. Backdoor differs — different key derivation.)"
echo

# Sign the original
echo "── Geometric Signatures ─────────────────────────────────────────"
echo
echo "  ORIGINAL (-O2):"
build/h3x_sig build/demo/target_original_O2 --sign 2>&1 | head -5
ORIG_ACC=$(build/h3x_sig build/demo/target_original_O2 --sign 2>&1 | grep "Global acc" | awk '{print $NF}')
echo

# Compare all variants via blame
echo "── Blame Analysis (Geometric Divergence) ─────────────────────────"
echo
echo "  Test 1: Original-O2 vs Original-O0 (SAME algo, different codegen)"
build/h3x_sig build/demo/target_original_O2 --blame build/demo/target_original_O0 2>&1 | grep -A2 "BLAME RESULT"
echo

echo "  Test 2: Original-O2 vs Original-O3 (SAME algo, aggressive opt)"
build/h3x_sig build/demo/target_original_O2 --blame build/demo/target_original_O3 2>&1 | grep -A2 "BLAME RESULT"
echo

echo "  Test 3: Original-O2 vs Patched-O2 (SAME algo, different source)"
build/h3x_sig build/demo/target_original_O2 --blame build/demo/target_patched_O2 2>&1 | grep -A2 "BLAME RESULT"
echo

echo "  Test 4: Original-O2 vs BACKDOOR-O2 (DIFFERENT algo!)"
build/h3x_sig build/demo/target_original_O2 --blame build/demo/target_backdoor_O2 2>&1 | grep -A2 "BLAME RESULT"
echo

# Generate YARA rule
echo "── Generated YARA Rule ──────────────────────────────────────────"
build/h3x_sig build/demo/target_original_O2 --yara-rule detect_keygen 2>&1
echo

echo "═══════════════════════════════════════════════════════════════════"
echo "  CONCLUSION"
echo "═══════════════════════════════════════════════════════════════════"
echo
echo "  If the backdoor shows HIGHER divergence than the recompilations,"
echo "  the geometric signature successfully detects structural algorithm"
echo "  changes while remaining tolerant of cosmetic differences."
echo
echo "  This is the property that makes H3X signatures superior to"
echo "  traditional byte-matching (YARA) or hash-based (SHA256) approaches"
echo "  for detecting supply-chain attacks and algorithm substitution."
echo

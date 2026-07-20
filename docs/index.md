---
layout: default
title: H3X User Guide
---

# H3X User Guide

A practical guide to using the H3X quaternionic binary geometry toolkit.

## Installation

```bash
git clone https://github.com/theQarchitect/h3x.git
cd h3x
make
make install  # installs to /usr/local/bin
```

### Requirements

- macOS 13+ or Linux (amd64/arm64)
- C compiler (clang or gcc)
- No external dependencies

### Verify Installation

```bash
h3x_analyze --help
h3x_grammar --library
```

---

## Quick Start

### 1. Analyze Any File

```bash
h3x_analyze /path/to/binary
```

This produces a structural report showing:
- **Token distribution** (the 5-state lattice profile)
- **Region breakdown** (STRUCTURAL / CONSTRAINED / EDITABLE percentages)
- **Confidence heatmap** (visual representation of structure)
- **Top editable regions** (safe modification targets)

### 2. Generate a Geometric Signature

```bash
h3x_sig /path/to/binary --sign
```

This outputs the **bound set** — a vector of per-segment accumulators that form the binary's geometric DNA. Use `--blame` to compare two files and find exactly where they diverge.

### 3. Identify an Unknown File

```bash
h3x_grammar --identify mystery_blob.bin
```

Matches the blob's transition geometry against the built-in library of 18 grammar fingerprints (ARM64, x86, Python, JSON, XML, shellcode, encrypted, etc.).

### 4. Auto-Learn from Your System

```bash
h3x_grammar --auto-learn
```

Scans all executables in your PATH, fingerprints each one, and clusters them by geometric similarity. Shows which binary families share structure.

---

## Tool Reference

### h3x_analyze — Structural Region Classification

```bash
h3x_analyze <file> [--warmup N] [--window N] [--json]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--warmup` | 200 | Frames before prediction starts |
| `--window` | 32 | Smoothing window width |
| `--json` | off | Output as JSON (for SIEM integration) |

**Output regions:**
- 🔴 **STRUCTURAL** (confidence > 70%): Format-determined bytes. Do NOT modify.
- 🟡 **CONSTRAINED** (50-70%): Soft structure. Modify carefully.
- 🟢 **EDITABLE** (< 50%): Content bytes. Safe to modify freely.

---

### h3x_sig — Geometric Signatures & Blame

```bash
h3x_sig <file> --sign                    # Print bound set signature
h3x_sig <file_a> --blame <file_b>        # Find divergence point
h3x_sig <file_a> --similarity <file_b>   # Compute similarity (0.0-1.0)
h3x_sig <file> --yara-rule <name>        # Generate geometric YARA rule
```

**Understanding similarity scores:**
- 0.95-1.0: Same binary or trivial difference
- 0.85-0.95: Same algorithm, different compilation
- 0.70-0.85: Related but structurally different
- < 0.70: Fundamentally different binaries

**The blame output** shows which segments diverged, with their orbit hashes. A segment divergence in a STRUCTURAL region = algorithm change. A divergence in EDITABLE = content difference (harmless).

---

### h3x_grammar — Language & Format Detection

```bash
h3x_grammar --identify <file>            # Identify format from geometry
h3x_grammar --auto-learn                 # Cluster all PATH binaries
h3x_grammar --library                    # List known fingerprints
h3x_grammar --profile <file>             # JSON fingerprint output
h3x_grammar --compare-runtime <pid> <binary>  # Detect injected code
```

**Grammar fingerprint features:**
- Identity density (% of zero-transitions)
- Transition energy (average magnitude)
- Bigram entropy (predictability)
- Autocorrelation (periodicity at byte/nibble boundaries)

---

### h3x_patch — Safe Binary Patching

```bash
h3x_patch <file> --list                  # List editable regions
h3x_patch <file> --inject <offset> <hex> # Patch at specific offset
h3x_patch <file> --auto <hex_payload>    # Auto-select largest region
h3x_patch <file> --embed <payload_file>  # Embed file into region
```

**Safety:** Refuses to patch STRUCTURAL regions unless `--force` is used. Verifies no structural cascade after patching.

---

### h3x_heal — Cascade Correction

```bash
h3x_heal <original> <patched> -o <healed>
h3x_heal <file> --patch <offset> <hex> -o <output>
```

After patching, the healer walks forward from the patch site and solves for corrective bytes that restore the original transition orbit. Due to Haar locality, cascades self-correct within 1-2 bytes — the healer confirms this.

---

### h3x_lucky — Structure-Aware Fuzzer

```bash
h3x_lucky <file> --fuzz <N> [--corpus dir]  # N mutation rounds
h3x_lucky <file> --fingerprint               # Structural digest
h3x_lucky <file_a> --diff <file_b>           # Compare fingerprints
```

**Mutations** (8 strategies): bitflip, byteflip, arithmetic, interesting values, block-zero, block-FF, swap, repeat.

Only mutates EDITABLE regions. After each mutation, re-fingerprints to detect if structural regions shifted (cascade detection). Interesting findings saved to corpus.

---

### h3x_sentinel — Runtime Memory Monitor

```bash
h3x_sentinel --watch <PID> [--interval ms]  # Continuous monitoring
h3x_sentinel --baseline <PID>               # Capture baseline
h3x_sentinel --check <PID>                  # One-shot check
```

**Alerts** (JSON to stdout):
- `HEAP_SPRAY_SUSPECT`: Identity density drop > 20%
- `CODE_CORRUPTION`: STRUCTURAL region → EDITABLE
- `INJECTION_SUSPECT`: Transition energy spike > 3σ

*Requires root or task_for_pid entitlement on macOS.*

---

### h3x_netwatch — Network Traffic Analysis

```bash
h3x_netwatch --demo              # Protocol fingerprinting demo
h3x_netwatch --stdin             # Pipe from tcpdump
h3x_netwatch --file <capture>    # Analyze saved capture
```

**Protocol classification rules:**
- Identity > 60%: STRUCTURED (DNS, database protocols)
- Identity 45-60%: PLAINTEXT (HTTP, SMTP, text protocols)
- Identity 35-42%: ENCRYPTED (TLS, SSH, compressed)

---

### h3x_tcp — TCP ISN Randomness Tester

```bash
h3x_tcp --generate-test random 500     # Test with good RNG
h3x_tcp --generate-test weak 500       # Test with weak generator
h3x_tcp --generate-test sequential 500 # Test with linear ISN
h3x_tcp --analyze <isn_file>           # Analyze captured ISNs
```

**Grades:** PASS (cryptographic), ACCEPTABLE (adequate), WARN (learnable), FAIL (predictable)

---

### h3x_syscall — Syscall Anomaly Detection

```bash
h3x_syscall --baseline <trace>           # Learn normal geometry
h3x_syscall --monitor <trace>            # Detect anomalies
h3x_syscall --compare <trace> <binary>   # Static vs runtime
```

Compares the predicted geometric profile (from static binary analysis) against actual runtime syscall traces. Divergence indicates injected code paths.

---

### h3x_apfs — System Geometric Soundness

```bash
h3x_apfs --scan-kexts      # Fingerprint kernel extensions
h3x_apfs --scan-firmware    # Analyze NVMe/boot firmware
h3x_apfs --scan-drivers     # Check system binaries
h3x_apfs --full             # All of the above
```

Flags geometrically anomalous system components:
- `LOW_ID`: Identity density below expected for category
- `HIGH_ENERGY`: Unusual transition patterns
- `ENCRYPTED?`: Kext with encrypted geometry (possible packed rootkit)

---

## Interpreting Results

### The Identity Density Scale

| Range | Meaning | Examples |
|-------|---------|---------|
| 95-100% | Zero-padded or constant | Universal binary stubs, empty regions |
| 70-95% | Sparse code + padding | Compiled binaries with alignment |
| 50-70% | Dense structured data | Text, XML, configs |
| 38-42% | Encrypted/compressed | TLS, zlib, encrypted firmware |
| < 38% | Unusual — investigate | Possibly corrupted or exotic encoding |

### Reading the Confidence Heatmap

```
░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████████████████████████████▒▒▒▒░░░
^                      ^                            ^       ^
EDITABLE           transition                 STRUCTURAL  EDITABLE
(headers)          boundary                    (code)      (tail)
```

---

## Integration

### With YARA

```bash
h3x_sig binary --yara-rule my_detection > rule.yar
```

### With SIEM (Splunk, ELK)

```bash
h3x_analyze binary --json | jq .
h3x_sentinel --watch $PID  # outputs JSON events
```

### With CI/CD

```bash
# In your build pipeline:
h3x_sig $NEW_BINARY --similarity $BASELINE
# If similarity < 0.85, fail the build (unexpected structural change)
```

---

## FAQ

**Q: Does this replace YARA?**  
A: No — it complements YARA. Use YARA for known byte patterns. Use H3X for structural detection that survives recompilation.

**Q: Can an attacker evade H3X?**  
A: An attacker would need to match the geometric *shape* of the target code while implementing different logic. This is significantly harder than changing bytes to avoid pattern matching.

**Q: Why not just use ssdeep?**  
A: ssdeep gives you a similarity score. H3X gives you similarity + blame + region classification + runtime monitoring + protocol detection. And it's tolerant of recompilation.

**Q: How fast is it?**  
A: 200+ MB/s for analysis. The bigram model is O(1) per byte.

---

*[Full Paper →](H3X_PAPER.md) | [Geometric Signatures →](GEOMETRIC_SIGNATURES.md) | [Repository →](https://github.com/theQarchitect/h3x)*

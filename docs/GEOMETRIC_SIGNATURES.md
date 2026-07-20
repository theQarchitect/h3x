# H3X Geometric Signatures for Security Professionals

**Author:** Derek Hinch | **Version:** 1.1 | **Date:** July 2026

## What This Is

A new class of binary signature that matches the **geometric shape** of code — not exact bytes. Built on the Hinch Wavelet Transition lattice, these signatures survive recompilation, optimization changes, padding differences, and variable renaming. They detect algorithm substitution, backdoors, and structural tampering.

## How It Works

### Two-Pass Boundary-Aware Analysis

**Pass 1 — Convex Hull Detection:**  
The bigram predictor scans the file and identifies confidence-based boundaries where the data transitions between STRUCTURAL (format-determined), CONSTRAINED (soft-structure), and EDITABLE (content-free) regions.

**Pass 2 — Per-Segment SGH5 Accumulator:**  
An accumulator walks the transition lattice within each segment, resetting at every boundary. Each segment gets:
- **Accumulator value** (BF64): rolling geometric hash sensitive to local structure
- **Orbit hash** (FNV-1a of token stream): exact match within a segment
- **Identity density**: ratio of zero-transitions (stability metric)

Together these form a **Bound Set** — the structural DNA of the binary.

### The SGH5 Walk

Each transition token (0-4) rotates the accumulator:
| Token | Meaning | Rotation Factor |
|-------|---------|----------------|
| 0 (-√2) | Max negative shift | -1.0 (full reversal) |
| 1 (-1/√2) | Unit negative | -0.5 |
| 2 (0) | Identity (no change) | φ = 0.618... (golden ratio) |
| 3 (+1/√2) | Unit positive | +0.5 |
| 4 (+√2) | Max positive shift | +1.0 |

The golden ratio for identity tokens creates sensitivity to their COUNT without being sensitive to exact position — giving tolerance to padding.

## What It's Tolerant Of

| Change | Effect on Signature | Detection? |
|--------|-------------------|------------|
| Recompilation (-O0 vs -O2 vs -O3) | ~87-97% similarity | NO (good) |
| Different variable names | Identical orbit hash in code segments | NO (good) |
| Padding changes | Only affects EDITABLE segments | NO (good) |
| NOP sleds / alignment | Identity density shifts, orbit unchanged | NO (good) |
| String literal changes | Only affects data segments | PARTIAL |

## What It Detects

| Attack | Signal | Confidence |
|--------|--------|-----------|
| Algorithm substitution (backdoor) | Orbit hash diverges in code segment | HIGH |
| Key weakening (reduced rotations) | Different accumulator in crypto function | HIGH |
| Function injection | New boundary appears, extra segment | HIGH |
| Supply chain (different compiler) | Slight orbit variation, same boundaries | MEDIUM |
| Binary patching (single instruction) | Local orbit change in one segment | MEDIUM |

## Demonstrated Results

From the target program demo (key derivation + MAC):

```
Original vs Patched (same algo, diff source):  87.5% similarity
Original vs O3 (same algo, aggressive opt):    87.5% similarity  
Original vs O0 (same algo, debug build):       96.9% similarity
Original vs BACKDOOR (weakened rotations):     90.6% similarity
                                               BUT: 43/60 segments DIVERGED
```

The backdoor scores high on raw similarity (because most of the binary is identical Mach-O overhead) but the **blame analysis** reveals 43 divergent segments — concentrated in the code section where the algorithm changed.

## Comparison with Existing Approaches

| Approach | Recompile-Tolerant? | Detects Backdoors? | Identifies WHERE? |
|----------|--------------------|--------------------|-------------------|
| SHA-256 hash | NO | YES (any change) | NO |
| YARA byte patterns | NO | PARTIAL | YES (offset) |
| ssdeep (fuzzy hash) | PARTIAL | PARTIAL | NO |
| **H3X Geometric Sig** | **YES** | **YES** | **YES (blame)** |

## EBNF Grammar Fingerprinting

Every data format conforming to a grammar produces a characteristic transition geometry. H3X can identify the underlying format without parsing:

| Format | Identity Density | Energy Profile | Characteristic |
|--------|-----------------|----------------|---------------|
| JSON | 55-65% | Low energy, periodic | Repeated `"` and `,` |
| XML | 50-60% | Medium, tag structure | `<>` patterns |
| Protobuf | 40-50% | Medium, varint patterns | Length-prefixed |
| ASN.1/DER | 45-55% | Mixed (tags + content) | TLV structure |
| ELF/Mach-O | 80-95% (padding), 45% (code) | Bimodal | Clear code/data split |
| Encrypted | 38-42% | Uniform ~0.6 | No learnable pattern |
| Compressed | 38-42% | Uniform ~0.6 | Indistinguishable from encrypted |

## Integration

### YARA Module (proposed syntax)
```yara
import "h3x"

rule detect_weakened_crypto {
    condition:
        h3x.bound_set_match([
            {off: 0x400, type: "CONSTRAINED", orbit: 0xed77a7650fb9c2f3},
            {off: 0x800, type: "STRUCTURAL", orbit: 0x80fc7676dec8b201},
        ], 2)
}
```

### JSON Output (for STIX/TAXII/MISP)
```json
{
    "type": "h3x-signature",
    "global_acc": 0.55593412,
    "global_orbit": "758b41b492e5eadf",
    "bound_set": [
        {"offset": "0x400", "type": "CONSTRAINED", "orbit": "ed77a7650fb9c2f3", "id%": 47.8},
        {"offset": "0x800", "type": "STRUCTURAL", "orbit": "80fc7676dec8b201", "id%": 99.5}
    ]
}
```

## Tools

| Tool | Purpose |
|------|---------|
| `h3x_sig --sign` | Generate bound set signature |
| `h3x_sig --blame` | Find divergence between two binaries |
| `h3x_sig --similarity` | Compute geometric similarity score |
| `h3x_sig --yara-rule` | Generate YARA rule from signature |
| `h3x_sentinel --watch` | Monitor runtime memory for drift |
| `h3x_netwatch --demo` | Classify network traffic protocols |

---
*QomputeAI 2024-2026 | Author: Derek Hinch*

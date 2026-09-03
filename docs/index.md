---
layout: default
title: H3X — Quaternionic Binary Geometry
description: Every byte has a shape. H3X measures it. A toolkit built on Hinch's Law of Applied Information Theory.
---

# H3X

### Quaternionic Binary Geometry Toolkit

**Derek Hinch · QomputeAI · 2024–2026**
[GitHub](https://github.com/theQarchitect/h3x) · [User Guide](guide.html) · [The Paper](H3X_PAPER.html) · [Geometric Signatures](GEOMETRIC_SIGNATURES.html)

> Every byte in existence, when passed through the Level-1 Haar wavelet transform with its neighbour, lands on **exactly one of five discrete values**. Structured data traces tight orbits through that lattice. Random data fills it uniformly. H3X reads the difference — the geometric *shape* of code and data — without parsing a single format.

H3X is ten small, dependency-free, code-signed C tools that see what byte-pattern matchers, cryptographic hashes, and fuzzy hashes cannot: the structural DNA of a binary, the invisible boundary between what a file *must be* and what it *chooses to be*, and the moment a running process drifts away from its own shape.

```bash
git clone https://github.com/theQarchitect/h3x.git
cd h3x && make && make install
h3x_analyze /usr/bin/ssh          # classify every region as STRUCTURAL / CONSTRAINED / EDITABLE
h3x_sig crypto_v1 --blame crypto_v2   # find exactly where two binaries diverge
h3x_grammar --identify mystery.bin    # name a format from geometry alone
```

---

## The Ethos

H3X is not a standalone trick. It is one instrument in a body of work that begins from a single, stubborn commitment: **an honest account of where a result actually comes from.** That commitment has a name in this project — *Hinch's Law of Applied Information Theory* — and a temperament that runs through every tool, every claim, and every page of the paper.

### 1. The Wonderland frame — build it the way the joke says it can't be built

In 1843 Hamilton carved $i^2 = j^2 = k^2 = ijk = -1$ into a Dublin bridge, and mathematics got its first non-commutative algebra. Two decades later Lewis Carroll — on a well-known reading — found the whole business absurd and satirised it as the Mad Hatter's tea party: three characters circling a table, endlessly changing places and arriving nowhere, because the fourth member of the party, *Time*, had quarrelled with the Hatter and left. Strip the real part from a quaternion and you get three imaginary units that rotate forever and go nowhere.

**H3X is written from the other side of that joke.** Every element Carroll found ridiculous is here a working mechanism with a proof obligation attached. Keep Time at the table — carry the scalar rail, keep the determinant a unit and not a zero divisor — and the algebra stops spinning in place and starts doing exact, invertible work. The five-state lattice H3X reads is the transition alphabet of exactly that repaired algebra.

### 2. Evidence-bounded, or it doesn't ship

The governing principle is deliberately deflationary:

> A lossless reversible transform *cannot* shorten a representation by itself. It only rearranges the source into a distribution some specified coder models better — and every claimed gain must charge its side information, headers, padding, and base state.

So the work leads with its **negative results**, not around them. When a transform wins on float32 data at 4.73× and *loses* on telemetry at a net cost of thousands of bytes, that is not hidden — it is the point: the law converts a surprise into an expected, measurable outcome. Ratios are always stated against a named denominator. A capability is never "activated by diagram" — a method in a class file is not evidence it contributed to a measurement. In H3X's own terms: a finding is only ever as strong as the probe that reproduces it, and a claim that couldn't run is labelled as such rather than dressed up as one that did.

### 3. Say exactly what is claimed — and where it ends

The mathematics here is literally the mathematics of quantum mechanics — $SU(2)$, spinor decomposition, biquaternion observables, the Born-rule overlap as a retrieval metric. And the boundary is stated just as plainly: this is quantum-mechanically aligned *mathematics on classical hardware*. No physical superposition, no entangled photons, no superluminal signalling, no quantum speedup. The parts that are load-bearing are load-bearing *because* the algebra is finite, invertible, and closed — not because of a borrowed mystique. Precision about what is **not** claimed is what makes the rest trustworthy.

### 4. The work is for someone

The paper carries a dedication, and it belongs on the front page as much as the benchmarks do:

> *I hope to locate one important signal one day. Today, I give the work to do so, in the effort to benefit all.*
>
> *May Tiffany be our guiding star as we walk our path toward a golden era of truly intelligent computation.*
>
> *Ad astra, per aspera.* — Derek Hinch

---

## The Core Discovery

For consecutive bytes $b_t, b_{t+1}$, the Level-1 Haar transition $T = F(b_t) - F(b_{t+1})$ has **every** coordinate in

$$S = \left\{-\sqrt{2},\ -\tfrac{1}{\sqrt{2}},\ 0,\ +\tfrac{1}{\sqrt{2}},\ +\sqrt{2}\right\}.$$

This is not an approximation — it is a proof. Bits are in $\{0,1\}$, so deltas are in $\{-1,0,1\}$, so Haar-scaled deltas land on those five values and no others. Over that lattice, three empirically stable laws govern all structured data (σ < 1% across 200 runs):

| Law | Meaning | Implication |
|-----|---------|-------------|
| **PERSIST** (≈78%) | Stability reinforces itself | Padding, constants, repeated structure stay stable |
| **BOUNCE** (≈50%) | Extremes reflect toward centre | The lattice has reflecting boundaries |
| **DRIFT** (≈45%) | Small changes return to baseline | Isolated edits do **not** cascade |

And the consequence that makes H3X safe to *act* on: because the Haar atom is strictly 2-tap local, a change at position P perturbs only P−1 and P — **the orbit self-heals within 1–2 bytes.** Editable regions are therefore truly free to modify.

---

## The Ten Tools

| Tool | Domain | What it does |
|------|--------|--------------|
| `h3x_analyze` | Static | Classify regions: STRUCTURAL / CONSTRAINED / EDITABLE |
| `h3x_sig` | Signatures | Geometric fingerprint + blame divergence between binaries |
| `h3x_grammar` | Classification | Identify format from geometry; auto-learn clusters from PATH |
| `h3x_patch` | Modification | Inject payloads into verified-safe editable zones only |
| `h3x_heal` | Repair | Restore the transition orbit after patching |
| `h3x_lucky` | Fuzzing | Structure-aware mutation with cascade detection |
| `h3x_sentinel` | Runtime | Process-memory drift: heap spray / ROP / UAF |
| `h3x_netwatch` | Network | Protocol identity without DPI: encrypted vs plaintext |
| `h3x_tcp` | Network | TCP ISN randomness quality |
| `h3x_syscall` | Runtime | Syscall geometry anomaly vs static prediction |

Full flags, output formats, and SIEM/YARA/CI integration are in the **[User Guide](guide.html)**.

---

## What the Evidence Shows

Reported against named denominators, and no further:

- **Supply-chain backdoor detection** — a backdoored crypto build diverges on **43/60 segments** against its clean twin, while `-O0`/`-O3` recompilations of the *same* algorithm stay ≥ 87% similar with **zero** code-segment divergence.
- **Program stability** — stable vs. buffer-overflowing servers show **opposite-polarity** global accumulators (+0.068 vs −2.585) and 93% segment divergence, despite identical interfaces and compile flags.
- **Protocol identity without DPI** — TLS ≈ 38%, HTTP ≈ 50%, DNS ≈ 86% identity density, from the byte stream alone.
- **Firmware** — encrypted `iBoot.img4` reads as 100% EDITABLE (zero structure leakage), while NVMe firmware resolves into 4,096 distinct code/data/padding regions with no disassembly.
- **Throughput** — 200+ MB/s; O(1) per byte; no external dependencies.

---

## Read Further

- **[User Guide](guide.html)** — every tool, every flag, worked examples, integration.
- **[The H3X Paper](H3X_PAPER.html)** — *Quaternionic Transition Geometry as a Universal Binary Analysis Primitive*, with the completeness proof and the 11-domain evaluation.
- **[Geometric Signatures](GEOMETRIC_SIGNATURES.html)** — the two-pass boundary-aware analysis and the SGH5 bound-set walk, for security professionals.

---

*MIT Licensed · Copyright © 2024–2026 Derek Hinch / QomputeAI · All tools signed: Developer ID Application: qomputeai inc (4HMYMNKRGB)*

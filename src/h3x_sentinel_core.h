/*
 * h3x_sentinel_core.h — region profiling and the --watch comparison, free of mach calls
 * so it can be tested on synthetic snapshots (tests/test_sentinel_watch.c).
 *
 * The comparison --watch used to make, and why it was wrong
 *   for (i...) compare current.regions[i] with baseline.regions[i]
 * Regions were matched by POSITION in the region list. A live process maps and unmaps
 * memory all the time, so after its first allocation every comparison was between two
 * unrelated regions and the same addresses were re-reported every scan. Protection bits
 * were not recorded, so "CODE_CORRUPTION" fired on heap memory.
 *
 * What it does now
 *   - A region is matched by (address, region size, protection). A mapping seen for the
 *     first time, or one that changed size or protection, is learned silently: the
 *     baseline becomes the current set of mappings each scan, and a persistent mapping
 *     keeps the profile it had when first seen.
 *   - Executable, non-writable regions: CODE_CORRUPTION when the sampled bytes changed
 *     (an FNV-1a of the sample). Code pages do not change; this is exact, not a density
 *     heuristic.
 *   - Writable, non-executable regions: HEAP_SPRAY_SUSPECT on an identity-density drop
 *     of more than 0.20, INJECTION_SUSPECT on a transition-energy rise above 1.5 (the
 *     original thresholds).
 *   - PROT_ESCALATION when a mapping at the same address and size gains WRITE while
 *     executable, or gains EXECUTE while writable.
 *   - Each (region, kind) is reported once when the condition starts, and again only
 *     after it has cleared and started again.
 */
#ifndef H3X_SENTINEL_CORE_H
#define H3X_SENTINEL_CORE_H

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define H3X_MAX_REGIONS 1024
#define H3X_SAMPLE_SIZE 4096

#define H3X_PROT_READ    0x1u
#define H3X_PROT_WRITE   0x2u
#define H3X_PROT_EXECUTE 0x4u

typedef struct {
    uint64_t address;
    uint64_t size;              /* bytes sampled (<= H3X_SAMPLE_SIZE) */
    uint64_t region_size;       /* size of the whole mapping */
    uint32_t prot;              /* H3X_PROT_* of the mapping */
    uint64_t sample_fnv;        /* FNV-1a 64 of the sampled bytes */
    float identity_density;
    float avg_confidence;
    float transition_energy;
} RegionProfile;

typedef struct {
    uint32_t n_regions;
    RegionProfile regions[H3X_MAX_REGIONS];
    long timestamp;
} Snapshot;

static inline void h3x_compute_tokens(uint8_t a, uint8_t b, uint8_t tok[8]) {
    for (int i = 0; i < 4; i++) {
        int ec = (a >> (7 - 2 * i)) & 1, oc = (a >> (6 - 2 * i)) & 1;
        int en = (b >> (7 - 2 * i)) & 1, on = (b >> (6 - 2 * i)) & 1;
        tok[i] = (uint8_t)((ec + oc) - (en + on) + 2);
        tok[4 + i] = (uint8_t)((ec - oc) - (en - on) + 2);
    }
}

static inline RegionProfile h3x_profile_buffer(const uint8_t *buf, size_t len, uint64_t addr,
                                               uint64_t region_size, uint32_t prot) {
    RegionProfile rp;
    memset(&rp, 0, sizeof rp);
    rp.address = addr;
    rp.size = len;
    rp.region_size = region_size;
    rp.prot = prot;
    uint64_t h = 1469598103934665603ULL;
    size_t n = len < H3X_SAMPLE_SIZE ? len : H3X_SAMPLE_SIZE;
    for (size_t i = 0; i < n; i++) { h ^= buf[i]; h *= 1099511628211ULL; }
    rp.sample_fnv = h;
    if (n < 2) return rp;
    uint32_t id_count = 0, total = 0;
    float energy_sum = 0;
    for (size_t i = 0; i + 1 < n; i++) {
        uint8_t tok[8];
        h3x_compute_tokens(buf[i], buf[i + 1], tok);
        for (int j = 0; j < 8; j++) {
            total++;
            if (tok[j] == 2) id_count++;
            energy_sum += fabsf((float)tok[j] - 2.0f);
        }
    }
    rp.identity_density = total > 0 ? (float)id_count / total : 0;
    rp.transition_energy = total > 0 ? energy_sum / total : 0;
    return rp;
}

/* ── watch state ───────────────────────────────────────────────────────────── */

enum { H3X_K_CODE = 1u, H3X_K_SPRAY = 2u, H3X_K_INJECT = 4u, H3X_K_PROT = 8u };

typedef struct {
    RegionProfile first;        /* the profile when this mapping was first seen */
    uint32_t active;            /* H3X_K_* conditions currently true (already reported) */
} WatchEntry;

typedef struct {
    uint32_t n;
    WatchEntry e[H3X_MAX_REGIONS];
    uint64_t learned;           /* mappings learned silently, lifetime */
    uint64_t reported;          /* events emitted, lifetime */
} WatchState;

typedef void (*h3x_emit_fn)(const char *kind, const RegionProfile *cur,
                            const RegionProfile *base, void *ctx);

static inline void h3x_watch_init(WatchState *w, const Snapshot *first) {
    memset(w, 0, sizeof *w);
    for (uint32_t i = 0; i < first->n_regions && i < H3X_MAX_REGIONS; i++) {
        w->e[w->n].first = first->regions[i];
        w->e[w->n].active = 0;
        w->n++;
    }
}

static inline int h3x_cmp_addr(uint64_t a, uint64_t b) { return a < b ? -1 : a > b ? 1 : 0; }

/* Compare one scan against the state, emit what started, and make the scan the new set of
 * tracked mappings. Both arrays are in ascending address order (mach_vm_region_recurse
 * walks the map upward), so this is a single merge pass. Returns events emitted. */
static inline unsigned h3x_watch_step(WatchState *w, const Snapshot *cur, h3x_emit_fn emit, void *ctx) {
    static WatchState next;     /* static: ~100 KB, too large for a fiber or small stack */
    memset(&next, 0, sizeof next);
    next.learned = w->learned;
    next.reported = w->reported;
    unsigned events = 0;
    uint32_t j = 0;
    for (uint32_t i = 0; i < cur->n_regions && next.n < H3X_MAX_REGIONS; i++) {
        const RegionProfile *c = &cur->regions[i];
        while (j < w->n && h3x_cmp_addr(w->e[j].first.address, c->address) < 0) j++;
        const WatchEntry *b = NULL;
        const WatchEntry *same_addr = NULL;
        if (j < w->n && w->e[j].first.address == c->address) {
            same_addr = &w->e[j];
            if (w->e[j].first.region_size == c->region_size && w->e[j].first.prot == c->prot) b = &w->e[j];
        }
        WatchEntry *out = &next.e[next.n++];
        if (b == NULL) {
            /* New mapping, or the mapping at this address changed shape: learn it. A
             * protection escalation on an otherwise identical mapping is the exception. */
            out->first = *c;
            out->active = 0;
            next.learned++;
            if (same_addr && same_addr->first.region_size == c->region_size) {
                uint32_t bp = same_addr->first.prot, cp = c->prot;
                int gained_w_on_x = (bp & H3X_PROT_EXECUTE) && !(bp & H3X_PROT_WRITE) && (cp & H3X_PROT_WRITE);
                int gained_x_on_w = (bp & H3X_PROT_WRITE) && !(bp & H3X_PROT_EXECUTE) && (cp & H3X_PROT_EXECUTE);
                if (gained_w_on_x || gained_x_on_w) {
                    if (!(same_addr->active & H3X_K_PROT)) { emit("PROT_ESCALATION", c, &same_addr->first, ctx); events++; }
                    out->first.prot = bp;           /* keep tracking against the original */
                    out->active = H3X_K_PROT;
                    next.learned--;
                }
            }
            continue;
        }
        out->first = b->first;
        uint32_t now = 0;
        uint32_t p = c->prot;
        if ((p & H3X_PROT_EXECUTE) && !(p & H3X_PROT_WRITE)) {
            if (c->size == b->first.size && c->sample_fnv != b->first.sample_fnv) now |= H3X_K_CODE;
        } else if ((p & H3X_PROT_WRITE) && !(p & H3X_PROT_EXECUTE)) {
            float id_delta = c->identity_density - b->first.identity_density;
            float en_delta = c->transition_energy - b->first.transition_energy;
            if (id_delta < -0.20f) now |= H3X_K_SPRAY;
            if (en_delta > 1.5f) now |= H3X_K_INJECT;
        } else if ((p & H3X_PROT_WRITE) && (p & H3X_PROT_EXECUTE)) {
            float en_delta = c->transition_energy - b->first.transition_energy;
            if (en_delta > 1.5f) now |= H3X_K_INJECT;
        }
        uint32_t started = now & ~b->active;
        if (started & H3X_K_CODE)   { emit("CODE_CORRUPTION", c, &b->first, ctx); events++; }
        if (started & H3X_K_SPRAY)  { emit("HEAP_SPRAY_SUSPECT", c, &b->first, ctx); events++; }
        if (started & H3X_K_INJECT) { emit("INJECTION_SUSPECT", c, &b->first, ctx); events++; }
        out->active = now;          /* matched means the original protection is back */
    }
    next.reported += events;
    *w = next;
    return events;
}

#endif

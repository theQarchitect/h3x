/* test_sentinel_watch.c — the --watch comparison on synthetic snapshots (no root, no target).
 * Build and run:  make test-sentinel-watch */
#include <stdio.h>
#include <string.h>
#include "../src/h3x_sentinel_core.h"

static int fails, checks;
#define CHECK(c, ...) do { checks++; if (c) printf("  ok   "); else { fails++; printf("  FAIL "); } printf(__VA_ARGS__); printf("\n"); } while (0)

typedef struct { int n; char kinds[64][32]; uint64_t addrs[64]; } Seen;
static void rec(const char *kind, const RegionProfile *cur, const RegionProfile *base, void *ctx) {
    (void)base; Seen *s = ctx;
    if (s->n < 64) { snprintf(s->kinds[s->n], 32, "%s", kind); s->addrs[s->n] = cur->address; s->n++; }
}
static int count(const Seen *s, const char *kind) { int k = 0; for (int i = 0; i < s->n; i++) if (!strcmp(s->kinds[i], kind)) k++; return k; }

/* Deterministic region content: "structured" bytes (low transition energy, high identity)
 * or "noisy" bytes (pseudo-random). */
static RegionProfile region(uint64_t addr, uint64_t size, uint32_t prot, int noisy, uint32_t seed) {
    static uint8_t buf[H3X_SAMPLE_SIZE];
    uint32_t x = seed * 2654435761u + 1;
    for (int i = 0; i < H3X_SAMPLE_SIZE; i++) {
        if (noisy) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; buf[i] = (uint8_t)x; }
        else buf[i] = (uint8_t)((i / 64) & 1 ? 0x00 : 0x00) | (uint8_t)(seed & 0x01);
    }
    return h3x_profile_buffer(buf, H3X_SAMPLE_SIZE, addr, size, prot);
}
static Snapshot snap;
static void reset(void) { memset(&snap, 0, sizeof snap); }
static void add(RegionProfile r) { snap.regions[snap.n_regions++] = r; }

#define RX (H3X_PROT_READ | H3X_PROT_EXECUTE)
#define RW (H3X_PROT_READ | H3X_PROT_WRITE)
#define RWX (H3X_PROT_READ | H3X_PROT_WRITE | H3X_PROT_EXECUTE)

int main(void) {
    static WatchState w; Seen s;

    printf("== a process that maps new memory (the flood seen on install)\n");
    reset(); add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x8000, RW, 0, 2)); add(region(0x20000, 0x8000, RW, 1, 3));
    h3x_watch_init(&w, &snap);
    reset(); add(region(0x0800, 0x400, RW, 1, 9));            /* a new mapping BELOW everything shifts every index */
    add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x8000, RW, 0, 2)); add(region(0x20000, 0x8000, RW, 1, 3));
    memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    CHECK(s.n == 0, "a mapping inserted below the others raises nothing");
    {   /* The comparison --watch used to make, on the same two snapshots: by position. */
        static Snapshot base0; memset(&base0, 0, sizeof base0);
        base0.regions[0] = region(0x1000, 0x4000, RX, 0, 1); base0.regions[1] = region(0x10000, 0x8000, RW, 0, 2);
        base0.regions[2] = region(0x20000, 0x8000, RW, 1, 3); base0.n_regions = 3;
        int old_events = 0;
        for (uint32_t i = 0; i < snap.n_regions && i < base0.n_regions; i++) {
            float id = snap.regions[i].identity_density - base0.regions[i].identity_density;
            float en = snap.regions[i].transition_energy - base0.regions[i].transition_energy;
            if (id < -0.20f) old_events++;
            if (id > 0.30f && base0.regions[i].identity_density < 0.5f) old_events++;
            if (en > 1.5f) old_events++;
        }
        CHECK(old_events > 0, "the old by-position comparison raises %d false alarm(s) on the same scans (so this test exercises the bug)", old_events);
    }
    CHECK(w.n == 4 && w.learned == 1, "the new mapping is learned silently (tracked=%u learned=%llu)", w.n, (unsigned long long)w.learned);
    for (int k = 0; k < 20; k++) { memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s); if (s.n) break; }
    CHECK(s.n == 0, "an unchanged process raises nothing over 20 scans");

    printf("== heap: report when a condition starts, not every scan\n");
    reset(); add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x8000, RW, 0, 2)); h3x_watch_init(&w, &snap);
    reset(); add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x8000, RW, 1, 7));   /* heap content went noisy */
    memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    CHECK(count(&s, "HEAP_SPRAY_SUSPECT") == 1 && s.addrs[0] == 0x10000, "a density drop on a writable region is reported once");
    int again = 0; for (int k = 0; k < 10; k++) { memset(&s, 0, sizeof s); again += h3x_watch_step(&w, &snap, rec, &s); }
    CHECK(again == 0, "the same standing condition is not reported again over 10 scans (got %d)", again);
    reset(); add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x8000, RW, 0, 2));
    memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    CHECK(s.n == 0, "the condition clearing raises nothing");
    reset(); add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x8000, RW, 1, 8));
    memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    CHECK(count(&s, "HEAP_SPRAY_SUSPECT") == 1, "and it is reported again when it starts again");

    printf("== code: exact, and only on executable mappings\n");
    reset(); add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x8000, RW, 1, 2)); h3x_watch_init(&w, &snap);
    reset(); add(region(0x1000, 0x4000, RX, 0, 0)); add(region(0x10000, 0x8000, RW, 1, 5));   /* code bytes changed; heap bytes changed */
    memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    CHECK(count(&s, "CODE_CORRUPTION") == 1 && s.addrs[0] == 0x1000, "changed bytes in an r-x region are CODE_CORRUPTION");
    CHECK(count(&s, "CODE_CORRUPTION") == 1, "changed bytes in an rw- region are never CODE_CORRUPTION");
    again = 0; for (int k = 0; k < 5; k++) { memset(&s, 0, sizeof s); again += h3x_watch_step(&w, &snap, rec, &s); }
    CHECK(again == 0, "corrupted code stays reported once");

    printf("== protection escalation\n");
    reset(); add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x8000, RW, 0, 2)); h3x_watch_init(&w, &snap);
    reset(); add(region(0x1000, 0x4000, RWX, 0, 1)); add(region(0x10000, 0x8000, RW | H3X_PROT_EXECUTE, 0, 2));
    memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    CHECK(count(&s, "PROT_ESCALATION") == 2, "r-x gaining write and rw- gaining execute are both reported (%d)", count(&s, "PROT_ESCALATION"));
    again = 0; for (int k = 0; k < 5; k++) { memset(&s, 0, sizeof s); again += h3x_watch_step(&w, &snap, rec, &s); }
    CHECK(again == 0, "a standing escalation is reported once (got %d)", again);
    reset(); add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x8000, RW, 0, 2));
    memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    reset(); add(region(0x1000, 0x4000, RWX, 0, 1)); add(region(0x10000, 0x8000, RW, 0, 2));
    memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    CHECK(count(&s, "PROT_ESCALATION") == 1, "after the original protection returns, a new escalation is reported again");

    printf("== mappings that change shape or go away\n");
    reset(); add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x8000, RW, 0, 2)); h3x_watch_init(&w, &snap);
    reset(); add(region(0x1000, 0x4000, RX, 0, 1)); add(region(0x10000, 0x10000, RW, 1, 3));   /* heap grew: new shape */
    memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    CHECK(s.n == 0, "a mapping that grew is re-learned, not compared to its old self");
    reset(); add(region(0x1000, 0x4000, RX, 0, 1));
    memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    CHECK(s.n == 0 && w.n == 1, "a mapping that disappeared is dropped (tracked=%u)", w.n);

    printf("== capacity\n");
    reset(); for (uint32_t i = 0; i < H3X_MAX_REGIONS; i++) add(region(0x100000 + (uint64_t)i * 0x10000, 0x8000, RW, 0, 2));
    h3x_watch_init(&w, &snap); memset(&s, 0, sizeof s); h3x_watch_step(&w, &snap, rec, &s);
    CHECK(s.n == 0 && w.n == H3X_MAX_REGIONS, "a full table (%d regions) compares cleanly", H3X_MAX_REGIONS);

    printf(fails ? "FAIL: test_sentinel_watch (%d of %d)\n" : "PASS: test_sentinel_watch (%d checks)\n", fails ? fails : checks, checks);
    return fails != 0;
}

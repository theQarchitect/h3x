/*
 * h3x_analyze — Binary Structural Analysis via Quaternionic Transition Geometry
 * ==============================================================================
 * Author: Derek Hinch
 *
 * Standalone C binary that reads any file and produces a structural analysis
 * report identifying EDITABLE vs STRUCTURAL regions using the Hinch Wavelet
 * Transition prediction confidence as a convex boundary indicator.
 *
 * Usage:
 *   h3x_analyze <file> [--json] [--warmup N] [--window N]
 *
 * Output:
 *   - Per-region classification (STRUCTURAL / CONSTRAINED / EDITABLE)
 *   - Prediction confidence heatmap
 *   - Token distribution statistics
 *   - Transition rule fingerprint
 *
 * Build:
 *   cc -O3 -o h3x_analyze h3x_analyze.c h3x_format.c -lm
 *
 * Theory: The 5-state quaternionic transition lattice has deterministic
 * orbits in format-structural regions and entropic orbits in content regions.
 * Prediction confidence is the convex indicator separating these domains.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "../include/h3x_format.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

#define DEFAULT_WARMUP   200
#define DEFAULT_WINDOW   32
#define MAX_REGIONS      4096

typedef enum {
    REGION_STRUCTURAL,   /* conf > 0.70: format-determined, do NOT modify */
    REGION_CONSTRAINED,  /* 0.50 < conf < 0.70: soft structure */
    REGION_EDITABLE      /* conf < 0.50: content/payload, safe to modify */
} RegionType;

typedef struct {
    uint32_t start;
    uint32_t end;
    RegionType type;
    float avg_confidence;
    float avg_energy;
} Region;

/* ═══════════════════════════════════════════════════════════════════════════
 * Bigram Predictor (per-coefficient Markov chain)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t bigram[8][5][5];  /* count[coeff][prev][next] */
    uint8_t  prev[8];
    uint32_t n_observed;
    uint32_t warmup;
} Predictor;

static void predictor_init(Predictor *p, uint32_t warmup) {
    memset(p, 0, sizeof(Predictor));
    for (int c = 0; c < 8; c++) p->prev[c] = 2; /* identity default */
    p->warmup = warmup;
    /* Laplace smoothing: start all counts at 1 */
    for (int c = 0; c < 8; c++)
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 5; j++)
                p->bigram[c][i][j] = 1;
}

static float predictor_feed(Predictor *p, const uint8_t tokens[8]) {
    float confidence = 0.0f;

    if (p->n_observed >= p->warmup) {
        for (int c = 0; c < 8; c++) {
            uint32_t *row = p->bigram[c][p->prev[c]];
            uint32_t total = 0, best = 0;
            for (int j = 0; j < 5; j++) {
                total += row[j];
                if (row[j] > best) best = row[j];
            }
            if (total > 0) confidence += (float)best / (float)total;
        }
        confidence /= 8.0f;
    }

    /* Learn */
    for (int c = 0; c < 8; c++) {
        p->bigram[c][p->prev[c]][tokens[c]]++;
        p->prev[c] = tokens[c];
    }
    p->n_observed++;

    return confidence;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Token computation (inline, no LUT needed for analysis)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void compute_tokens(uint8_t b_curr, uint8_t b_next, uint8_t tokens[8]) {
    for (int i = 0; i < 4; i++) {
        int even_c = (b_curr >> (7 - 2*i)) & 1;
        int odd_c  = (b_curr >> (6 - 2*i)) & 1;
        int even_n = (b_next >> (7 - 2*i)) & 1;
        int odd_n  = (b_next >> (6 - 2*i)) & 1;

        /* Haar: cA = (even+odd)/√2, cD = (even-odd)/√2
         * Diff scaled by √2: (cA_c - cA_n)*√2 = (even_c+odd_c) - (even_n+odd_n) */
        int d_ca = (even_c + odd_c) - (even_n + odd_n); /* ∈ {-2,-1,0,1,2} */
        int d_cd = (even_c - odd_c) - (even_n - odd_n); /* ∈ {-2,-1,0,1,2} */

        tokens[i]     = (uint8_t)(d_ca + 2); /* [0..4] */
        tokens[4 + i] = (uint8_t)(d_cd + 2); /* [0..4] */
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Region Detection
 * ═══════════════════════════════════════════════════════════════════════════ */

static RegionType classify_confidence(float conf) {
    if (conf > 0.70f) return REGION_STRUCTURAL;
    if (conf > 0.50f) return REGION_CONSTRAINED;
    return REGION_EDITABLE;
}

static const char *region_name(RegionType t) {
    switch (t) {
        case REGION_STRUCTURAL: return "STRUCTURAL";
        case REGION_CONSTRAINED: return "CONSTRAINED";
        case REGION_EDITABLE: return "EDITABLE";
    }
    return "UNKNOWN";
}

static const char *region_color(RegionType t) {
    switch (t) {
        case REGION_STRUCTURAL: return "\033[31m"; /* red */
        case REGION_CONSTRAINED: return "\033[33m"; /* yellow */
        case REGION_EDITABLE: return "\033[32m"; /* green */
    }
    return "\033[0m";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main Analysis
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "H3X Structural Analyzer — Hinch Wavelet Transition Geometry\n");
        fprintf(stderr, "Usage: %s <file> [--warmup N] [--window N] [--json]\n", argv[0]);
        fprintf(stderr, "\nIdentifies EDITABLE vs STRUCTURAL regions via quaternionic\n");
        fprintf(stderr, "transition prediction confidence (convex boundary detection).\n");
        return 1;
    }

    const char *filepath = argv[1];
    int warmup = DEFAULT_WARMUP;
    int window = DEFAULT_WINDOW;
    int json_output = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--warmup") == 0 && i + 1 < argc)
            warmup = atoi(argv[++i]);
        else if (strcmp(argv[i], "--window") == 0 && i + 1 < argc)
            window = atoi(argv[++i]);
        else if (strcmp(argv[i], "--json") == 0)
            json_output = 1;
    }

    /* Read file */
    FILE *f = fopen(filepath, "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = (uint8_t *)malloc(file_size);
    if (!data) { fprintf(stderr, "OOM\n"); fclose(f); return 1; }
    fread(data, 1, file_size, f);
    fclose(f);

    size_t n = (size_t)file_size;

    /* Phase 1: Compute per-position confidence scores */
    float *scores = (float *)calloc(n, sizeof(float));
    uint32_t token_dist[5] = {0};
    uint32_t energy_hist[9] = {0}; /* energy 0..8 */

    Predictor pred;
    predictor_init(&pred, (uint32_t)warmup);

    for (size_t i = 0; i + 1 < n; i++) {
        uint8_t tokens[8];
        compute_tokens(data[i], data[i + 1], tokens);
        scores[i] = predictor_feed(&pred, tokens);

        /* Stats */
        int energy = 0;
        for (int j = 0; j < 8; j++) {
            token_dist[tokens[j]]++;
            energy += abs((int)tokens[j] - 2);
        }
        if (energy < 9) energy_hist[energy]++;
    }

    /* Phase 2: Smooth with sliding window */
    float *smooth = (float *)calloc(n, sizeof(float));
    for (size_t i = 0; i < n - 1; i++) {
        float sum = 0.0f;
        int count = 0;
        for (int w = -window/2; w <= window/2; w++) {
            int idx = (int)i + w;
            if (idx >= 0 && idx < (int)(n - 1)) {
                sum += scores[idx];
                count++;
            }
        }
        smooth[i] = count > 0 ? sum / count : 0.0f;
    }

    /* Phase 3: Detect regions */
    Region regions[MAX_REGIONS];
    int n_regions = 0;

    RegionType current_type = classify_confidence(smooth[0]);
    uint32_t region_start = 0;

    for (size_t i = 1; i < n - 1; i++) {
        RegionType t = classify_confidence(smooth[i]);
        if (t != current_type) {
            if (n_regions < MAX_REGIONS) {
                regions[n_regions].start = region_start;
                regions[n_regions].end = (uint32_t)i;
                regions[n_regions].type = current_type;
                /* Compute average confidence for region */
                float avg = 0;
                for (uint32_t j = region_start; j < (uint32_t)i; j++) avg += smooth[j];
                regions[n_regions].avg_confidence = avg / (i - region_start);
                n_regions++;
            }
            current_type = t;
            region_start = (uint32_t)i;
        }
    }
    /* Final region */
    if (n_regions < MAX_REGIONS) {
        regions[n_regions].start = region_start;
        regions[n_regions].end = (uint32_t)(n - 1);
        regions[n_regions].type = current_type;
        n_regions++;
    }

    /* ═════════ OUTPUT ═════════ */

    if (json_output) {
        printf("{\n");
        printf("  \"file\": \"%s\",\n", filepath);
        printf("  \"size\": %ld,\n", file_size);
        printf("  \"warmup\": %d,\n", warmup);
        printf("  \"window\": %d,\n", window);
        printf("  \"n_regions\": %d,\n", n_regions);
        printf("  \"token_distribution\": [%u, %u, %u, %u, %u],\n",
               token_dist[0], token_dist[1], token_dist[2], token_dist[3], token_dist[4]);

        /* Region totals */
        uint32_t struct_bytes = 0, constr_bytes = 0, edit_bytes = 0;
        for (int i = 0; i < n_regions; i++) {
            uint32_t sz = regions[i].end - regions[i].start;
            switch (regions[i].type) {
                case REGION_STRUCTURAL: struct_bytes += sz; break;
                case REGION_CONSTRAINED: constr_bytes += sz; break;
                case REGION_EDITABLE: edit_bytes += sz; break;
            }
        }
        printf("  \"structural_bytes\": %u,\n", struct_bytes);
        printf("  \"constrained_bytes\": %u,\n", constr_bytes);
        printf("  \"editable_bytes\": %u,\n", edit_bytes);
        printf("  \"regions\": [\n");
        for (int i = 0; i < n_regions; i++) {
            printf("    {\"start\": %u, \"end\": %u, \"size\": %u, \"type\": \"%s\", \"confidence\": %.3f}%s\n",
                   regions[i].start, regions[i].end,
                   regions[i].end - regions[i].start,
                   region_name(regions[i].type),
                   regions[i].avg_confidence,
                   i < n_regions - 1 ? "," : "");
        }
        printf("  ]\n}\n");
    } else {
        /* Human-readable report */
        printf("═══════════════════════════════════════════════════════════════════\n");
        printf("  H3X STRUCTURAL ANALYSIS REPORT\n");
        printf("  Hinch Wavelet Transition Geometry — Convex Region Detection\n");
        printf("═══════════════════════════════════════════════════════════════════\n\n");
        printf("  File:   %s\n", filepath);
        printf("  Size:   %ld bytes\n", file_size);
        printf("  Warmup: %d frames, Window: %d\n\n", warmup, window);

        /* Token distribution */
        uint64_t total_tokens = 0;
        for (int i = 0; i < 5; i++) total_tokens += token_dist[i];
        float id_pct = total_tokens > 0 ? token_dist[2] * 100.0f / total_tokens : 0;

        printf("  Token Distribution:\n");
        const char *tok_names[] = {"-√2", "-1/√2", "0(id)", "+1/√2", "+√2"};
        for (int i = 0; i < 5; i++) {
            float pct = total_tokens > 0 ? token_dist[i] * 100.0f / total_tokens : 0;
            int bar = (int)(pct / 2);
            printf("    %6s: %6.1f%% ", tok_names[i], pct);
            for (int b = 0; b < bar; b++) printf("█");
            printf("\n");
        }
        printf("    Identity density: %.1f%%\n\n", id_pct);

        /* Region summary */
        uint32_t struct_bytes = 0, constr_bytes = 0, edit_bytes = 0;
        for (int i = 0; i < n_regions; i++) {
            uint32_t sz = regions[i].end - regions[i].start;
            switch (regions[i].type) {
                case REGION_STRUCTURAL: struct_bytes += sz; break;
                case REGION_CONSTRAINED: constr_bytes += sz; break;
                case REGION_EDITABLE: edit_bytes += sz; break;
            }
        }

        printf("  Region Breakdown:\n");
        printf("    %sSTRUCTURAL\033[0m (do NOT modify): %8u bytes (%5.1f%%)\n",
               region_color(REGION_STRUCTURAL), struct_bytes, struct_bytes * 100.0f / n);
        printf("    %sCONSTRAINED\033[0m (modify carefully): %7u bytes (%5.1f%%)\n",
               region_color(REGION_CONSTRAINED), constr_bytes, constr_bytes * 100.0f / n);
        printf("    %sEDITABLE\033[0m (safe to modify):   %8u bytes (%5.1f%%)\n",
               region_color(REGION_EDITABLE), edit_bytes, edit_bytes * 100.0f / n);
        printf("    Total regions: %d\n\n", n_regions);

        /* Region table */
        printf("  Regions (showing first 50):\n");
        printf("  %8s %8s %6s %-12s %5s  Content\n",
               "Start", "End", "Size", "Type", "Conf");
        printf("  ────────────────────────────────────────────────────────────\n");

        int shown = 0;
        for (int i = 0; i < n_regions && shown < 50; i++) {
            uint32_t sz = regions[i].end - regions[i].start;
            if (sz < 4) continue;

            /* Content preview */
            char preview[41] = {0};
            uint32_t plen = sz < 20 ? sz : 20;
            int is_ascii = 1;
            for (uint32_t j = 0; j < plen && j < 16; j++) {
                uint8_t b = data[regions[i].start + j];
                if (b < 32 || b > 126) { is_ascii = 0; break; }
            }
            if (is_ascii) {
                snprintf(preview, 40, "\"%.*s\"", (int)(plen < 30 ? plen : 30),
                         data + regions[i].start);
            } else {
                for (uint32_t j = 0; j < 10 && j < plen; j++)
                    sprintf(preview + j*2, "%02x", data[regions[i].start + j]);
            }

            printf("  %s%8u %8u %6u %-12s %4.0f%%%s %s\n",
                   region_color(regions[i].type),
                   regions[i].start, regions[i].end, sz,
                   region_name(regions[i].type),
                   regions[i].avg_confidence * 100,
                   "\033[0m",
                   preview);
            shown++;
        }

        /* Heatmap */
        printf("\n  Confidence Heatmap (█=structural ▒=constrained ░=editable):\n  ");
        int step = n > 70 ? (int)(n / 70) : 1;
        for (size_t i = 0; i < n - 1 && i / step < 70; i += step) {
            float s = smooth[i];
            if (s > 0.70f) printf("█");
            else if (s > 0.50f) printf("▒");
            else printf("░");
        }
        printf("\n\n");

        /* Editable regions summary */
        printf("  Top Editable Regions (modification targets):\n");
        /* Sort by size descending */
        int edit_indices[MAX_REGIONS];
        int n_edit = 0;
        for (int i = 0; i < n_regions; i++)
            if (regions[i].type == REGION_EDITABLE)
                edit_indices[n_edit++] = i;

        /* Simple bubble sort for top 10 */
        for (int i = 0; i < n_edit - 1 && i < 10; i++) {
            for (int j = i + 1; j < n_edit; j++) {
                uint32_t si = regions[edit_indices[i]].end - regions[edit_indices[i]].start;
                uint32_t sj = regions[edit_indices[j]].end - regions[edit_indices[j]].start;
                if (sj > si) { int tmp = edit_indices[i]; edit_indices[i] = edit_indices[j]; edit_indices[j] = tmp; }
            }
        }

        for (int i = 0; i < n_edit && i < 10; i++) {
            Region *r = &regions[edit_indices[i]];
            uint32_t sz = r->end - r->start;
            printf("    %d. Offset 0x%04X-0x%04X (%u bytes, conf=%.0f%%)\n",
                   i + 1, r->start, r->end, sz, r->avg_confidence * 100);
        }

        printf("\n═══════════════════════════════════════════════════════════════════\n");
    }

    free(data);
    free(scores);
    free(smooth);
    return 0;
}

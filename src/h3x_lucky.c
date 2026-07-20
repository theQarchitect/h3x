/*
 * h3x_lucky — Structure-Aware Fuzzer with Cascade Detection
 * ==========================================================
 * Author: Derek Hinch
 *
 * Mutations are applied ONLY to EDITABLE regions (geometrically safe zones).
 * After each mutation, the file is re-analyzed to detect if structural regions
 * shifted — indicating a "cascade" where content change affects format parsing.
 *
 * Interesting findings are saved to a corpus directory.
 *
 * Modes:
 *   --fuzz N        : Run N mutation rounds, report cascades
 *   --cascade       : Specifically hunt for cascade-inducing mutations
 *   --fingerprint   : Generate structural fingerprint (digest of region map)
 *   --diff A B      : Compare structural fingerprints of two files
 *
 * Build:
 *   cc -O3 -o h3x_lucky h3x_lucky.c -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/stat.h>
#include "../include/h3x_format.h"

#define MAX_REGIONS 4096
#define WARMUP 200
#define WINDOW 32

typedef enum { R_STRUCTURAL, R_CONSTRAINED, R_EDITABLE } RType;
typedef struct { uint32_t start, end; RType type; float conf; } Region;

/* ═══════════════════════════════════════════════════════════════════════════ */

static void compute_tokens(uint8_t a, uint8_t b, uint8_t tok[8]) {
    for (int i = 0; i < 4; i++) {
        int ec=(a>>(7-2*i))&1, oc=(a>>(6-2*i))&1;
        int en=(b>>(7-2*i))&1, on=(b>>(6-2*i))&1;
        tok[i]   = (uint8_t)((ec+oc)-(en+on)+2);
        tok[4+i] = (uint8_t)((ec-oc)-(en-on)+2);
    }
}

typedef struct { uint32_t bigram[8][5][5]; uint8_t prev[8]; uint32_t n; } Pred;

static void pred_init(Pred *p) {
    memset(p,0,sizeof(Pred));
    for(int c=0;c<8;c++){p->prev[c]=2;for(int i=0;i<5;i++)for(int j=0;j<5;j++)p->bigram[c][i][j]=1;}
}

static float pred_feed(Pred *p, const uint8_t tok[8]) {
    float conf=0;
    if(p->n>=WARMUP){for(int c=0;c<8;c++){uint32_t*row=p->bigram[c][p->prev[c]];uint32_t tot=0,best=0;for(int j=0;j<5;j++){tot+=row[j];if(row[j]>best)best=row[j];}if(tot>0)conf+=(float)best/tot;}conf/=8.0f;}
    for(int c=0;c<8;c++){p->bigram[c][p->prev[c]][tok[c]]++;p->prev[c]=tok[c];}
    p->n++;
    return conf;
}

static int find_regions(const uint8_t *data, size_t n, Region *regions) {
    Pred pred; pred_init(&pred);
    float *scores=calloc(n,sizeof(float));
    for(size_t i=0;i+1<n;i++){uint8_t tok[8];compute_tokens(data[i],data[i+1],tok);scores[i]=pred_feed(&pred,tok);}
    float *smooth=calloc(n,sizeof(float));
    for(size_t i=0;i<n-1;i++){float s=0;int c=0;for(int w=-WINDOW/2;w<=WINDOW/2;w++){int idx=(int)i+w;if(idx>=0&&idx<(int)(n-1)){s+=scores[idx];c++;}}smooth[i]=c>0?s/c:0;}
    int nr=0;
    RType cur=smooth[0]>0.7f?R_STRUCTURAL:smooth[0]>0.5f?R_CONSTRAINED:R_EDITABLE;
    uint32_t rs=0;
    for(size_t i=1;i<n-1&&nr<MAX_REGIONS;i++){RType t=smooth[i]>0.7f?R_STRUCTURAL:smooth[i]>0.5f?R_CONSTRAINED:R_EDITABLE;if(t!=cur){regions[nr++]=(Region){rs,(uint32_t)i,cur,0};cur=t;rs=(uint32_t)i;}}
    if(nr<MAX_REGIONS)regions[nr++]=(Region){rs,(uint32_t)(n-1),cur,0};
    free(scores);free(smooth);
    return nr;
}

/* Structural fingerprint: hash of region types at fixed sample points */
static uint64_t fingerprint(const uint8_t *data, size_t n) {
    Region regions[MAX_REGIONS];
    int nr = find_regions(data, n, regions);
    uint64_t hash = 0xcbf29ce484222325ULL; /* FNV-1a offset */
    for (int i = 0; i < nr; i++) {
        hash ^= (uint64_t)regions[i].type;
        hash *= 0x100000001b3ULL;
        hash ^= (uint64_t)(regions[i].end - regions[i].start);
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Mutation Strategies (applied only to editable regions)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    MUT_BITFLIP,      /* Flip a single bit */
    MUT_BYTEFLIP,     /* Flip entire byte */
    MUT_ARITH,        /* ±1..±35 arithmetic */
    MUT_INTERESTING,  /* Known interesting values (0, 0xFF, 0x7F, 0x80) */
    MUT_BLOCK_ZERO,   /* Zero a small block */
    MUT_BLOCK_FF,     /* Fill with 0xFF */
    MUT_SWAP,         /* Swap two bytes within region */
    MUT_REPEAT,       /* Repeat a nearby byte */
    N_MUTATIONS
} MutationType;

static void apply_mutation(uint8_t *data, uint32_t start, uint32_t end, MutationType mt, uint32_t seed) {
    uint32_t sz = end - start;
    if (sz == 0) return;
    uint32_t off = start + (seed % sz);

    switch (mt) {
        case MUT_BITFLIP:
            data[off] ^= (1 << (seed / sz % 8));
            break;
        case MUT_BYTEFLIP:
            data[off] ^= 0xFF;
            break;
        case MUT_ARITH:
            data[off] += (uint8_t)((seed >> 16) % 71 - 35);
            break;
        case MUT_INTERESTING: {
            uint8_t vals[] = {0x00, 0x01, 0x7F, 0x80, 0xFF, 0xFE, 0x41};
            data[off] = vals[(seed >> 8) % 7];
            break;
        }
        case MUT_BLOCK_ZERO: {
            uint32_t blen = 1 + (seed >> 12) % 8;
            if (off + blen > end) blen = end - off;
            memset(data + off, 0, blen);
            break;
        }
        case MUT_BLOCK_FF: {
            uint32_t blen = 1 + (seed >> 12) % 8;
            if (off + blen > end) blen = end - off;
            memset(data + off, 0xFF, blen);
            break;
        }
        case MUT_SWAP:
            if (sz > 1) {
                uint32_t off2 = start + ((seed >> 16) % sz);
                uint8_t tmp = data[off]; data[off] = data[off2]; data[off2] = tmp;
            }
            break;
        case MUT_REPEAT:
            if (off > start) data[off] = data[off - 1];
            break;
        default: break;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "h3x_lucky — Structure-Aware Fuzzer & Cascade Detector\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s <file> --fuzz <N> [--corpus dir]\n", argv[0]);
        fprintf(stderr, "  %s <file> --fingerprint\n", argv[0]);
        fprintf(stderr, "  %s <file_a> --diff <file_b>\n", argv[0]);
        fprintf(stderr, "\nMutates EDITABLE regions, detects structural cascades.\n");
        return 1;
    }

    const char *filepath = argv[1];
    const char *mode = argv[2];

    FILE *f = fopen(filepath, "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f,0,SEEK_END); long fsize=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t *orig = malloc(fsize);
    fread(orig,1,fsize,f); fclose(f);

    if (!strcmp(mode, "--fingerprint")) {
        uint64_t fp = fingerprint(orig, (size_t)fsize);
        Region regions[MAX_REGIONS];
        int nr = find_regions(orig, (size_t)fsize, regions);
        int n_struct=0, n_constr=0, n_edit=0;
        uint32_t s_sz=0, c_sz=0, e_sz=0;
        for(int i=0;i<nr;i++){uint32_t sz=regions[i].end-regions[i].start;
            switch(regions[i].type){case R_STRUCTURAL:n_struct++;s_sz+=sz;break;case R_CONSTRAINED:n_constr++;c_sz+=sz;break;case R_EDITABLE:n_edit++;e_sz+=sz;break;}}

        printf("H3X Structural Fingerprint: %016llx\n", (unsigned long long)fp);
        printf("  File: %s (%ld bytes)\n", filepath, fsize);
        printf("  Regions: %d total (%d structural, %d constrained, %d editable)\n",
               nr, n_struct, n_constr, n_edit);
        printf("  Bytes: %u structural, %u constrained, %u editable\n", s_sz, c_sz, e_sz);
        free(orig); return 0;
    }

    if (!strcmp(mode, "--diff") && argc >= 4) {
        FILE *fb = fopen(argv[3], "rb");
        if (!fb) { perror("fopen B"); free(orig); return 1; }
        fseek(fb,0,SEEK_END); long bsize=ftell(fb); fseek(fb,0,SEEK_SET);
        uint8_t *datab = malloc(bsize); fread(datab,1,bsize,fb); fclose(fb);

        uint64_t fp_a = fingerprint(orig, (size_t)fsize);
        uint64_t fp_b = fingerprint(datab, (size_t)bsize);

        printf("Structural Diff:\n");
        printf("  A: %s → fingerprint %016llx\n", filepath, (unsigned long long)fp_a);
        printf("  B: %s → fingerprint %016llx\n", argv[3], (unsigned long long)fp_b);
        printf("  Match: %s\n", fp_a == fp_b ? "IDENTICAL STRUCTURE" : "DIFFERENT STRUCTURE");

        if (fp_a != fp_b) {
            Region ra[MAX_REGIONS], rb[MAX_REGIONS];
            int nra = find_regions(orig, (size_t)fsize, ra);
            int nrb = find_regions(datab, (size_t)bsize, rb);
            printf("  Regions: A=%d, B=%d (delta=%d)\n", nra, nrb, nrb-nra);

            int type_changes = 0;
            int compare_n = nra < nrb ? nra : nrb;
            for (int i=0;i<compare_n;i++) {
                if (ra[i].type != rb[i].type) type_changes++;
            }
            printf("  Type changes: %d / %d regions\n", type_changes, compare_n);
        }

        free(orig); free(datab); return 0;
    }

    if (!strcmp(mode, "--fuzz") && argc >= 4) {
        int n_rounds = atoi(argv[3]);
        const char *corpus_dir = NULL;
        for (int i=4;i<argc;i++) if(!strcmp(argv[i],"--corpus")&&i+1<argc) corpus_dir=argv[++i];

        if (corpus_dir) { mkdir(corpus_dir, 0755); }

        /* Initial analysis */
        Region regions[MAX_REGIONS];
        int nr = find_regions(orig, (size_t)fsize, regions);
        uint64_t orig_fp = fingerprint(orig, (size_t)fsize);

        /* Collect editable regions */
        int edit_idx[MAX_REGIONS]; int n_edit = 0;
        for (int i=0;i<nr;i++) if(regions[i].type==R_EDITABLE) edit_idx[n_edit++]=i;

        if (n_edit == 0) {
            printf("No editable regions found — file is fully structural.\n");
            free(orig); return 0;
        }

        printf("h3x_lucky: Fuzzing %s (%ld bytes)\n", filepath, fsize);
        printf("  Editable regions: %d (targeting only these)\n", n_edit);
        printf("  Rounds: %d\n", n_rounds);
        printf("  Original fingerprint: %016llx\n\n", (unsigned long long)orig_fp);

        srand((unsigned int)time(NULL));
        int cascades_found = 0;
        int total_mutations = 0;

        printf("  %6s %8s %8s %10s %8s %s\n",
               "Round", "Offset", "MutType", "NewFP", "Cascade", "Note");
        printf("  " "────────────────────────────────────────────────────────────\n");

        for (int round = 0; round < n_rounds; round++) {
            /* Make a copy */
            uint8_t *mutant = malloc(fsize);
            memcpy(mutant, orig, fsize);

            /* Pick random editable region */
            int ri = edit_idx[rand() % n_edit];
            Region *r = &regions[ri];

            /* Pick random mutation */
            MutationType mt = (MutationType)(rand() % N_MUTATIONS);
            uint32_t seed = (uint32_t)rand();

            /* Apply mutation */
            uint32_t off = r->start + (seed % (r->end - r->start));
            apply_mutation(mutant, r->start, r->end, mt, seed);
            total_mutations++;

            /* Re-fingerprint */
            uint64_t new_fp = fingerprint(mutant, (size_t)fsize);
            int is_cascade = (new_fp != orig_fp);

            if (is_cascade) {
                cascades_found++;
                const char *mt_name[] = {"bitflip","byteflip","arith","interesting","zero","ff","swap","repeat"};
                printf("  %6d 0x%06X %8s %016llx %8s CASCADE!\n",
                       round, off, mt_name[mt], (unsigned long long)new_fp, "YES");

                /* Save to corpus */
                if (corpus_dir) {
                    char path[512];
                    snprintf(path, sizeof(path), "%s/cascade_%04d_mt%d_off%06x.bin",
                             corpus_dir, cascades_found, mt, off);
                    FILE *cf = fopen(path, "wb");
                    if (cf) { fwrite(mutant, 1, fsize, cf); fclose(cf); }
                }
            }

            free(mutant);
        }

        printf("\n  ═══ RESULTS ═══\n");
        printf("  Total mutations:    %d\n", total_mutations);
        printf("  Cascades found:     %d (%.2f%%)\n",
               cascades_found, cascades_found * 100.0 / total_mutations);
        printf("  Safe mutations:     %d\n", total_mutations - cascades_found);
        printf("\n  Interpretation:\n");
        if (cascades_found == 0) {
            printf("    All EDITABLE mutations were structurally safe.\n");
            printf("    The convex boundary is TIGHT — editable regions are truly free.\n");
        } else {
            printf("    %d mutations in 'editable' regions caused structural shifts.\n", cascades_found);
            printf("    These are BOUNDARY CASES — the convex hull has soft edges here.\n");
            printf("    Corpus saved for further analysis.\n");
        }

        free(orig); return 0;
    }

    fprintf(stderr, "Unknown mode: %s\n", mode);
    free(orig); return 1;
}

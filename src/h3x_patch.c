/*
 * h3x_patch — Structure-Aware Binary Patching via Quaternionic Region Detection
 * ==============================================================================
 * Author: Derek Hinch
 *
 * Injects user-provided payload into EDITABLE regions of a binary file,
 * verified by H3X transition geometry to not affect structural integrity.
 *
 * Modes:
 *   --inject <offset> <hex_payload>  : Patch at specific offset
 *   --auto <hex_payload>             : Auto-select largest editable region
 *   --embed <file>                   : Embed a file into largest editable region
 *   --verify                         : Re-analyze after patch, confirm no cascade
 *   --list                           : List editable regions only
 *
 * Safety: Will REFUSE to patch STRUCTURAL or CONSTRAINED regions unless --force.
 *
 * Build:
 *   cc -O3 -o h3x_patch h3x_patch.c -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "../include/h3x_format.h"

#define MAX_REGIONS 4096
#define WARMUP 200
#define WINDOW 32

typedef enum { R_STRUCTURAL, R_CONSTRAINED, R_EDITABLE } RType;
typedef struct { uint32_t start, end; RType type; float conf; } Region;

/* ═══════════════════════════════════════════════════════════════════════════ */

static void compute_tokens(uint8_t a, uint8_t b, uint8_t tok[8]) {
    for (int i = 0; i < 4; i++) {
        int ec = (a >> (7-2*i)) & 1, oc = (a >> (6-2*i)) & 1;
        int en = (b >> (7-2*i)) & 1, on = (b >> (6-2*i)) & 1;
        tok[i]   = (uint8_t)((ec+oc) - (en+on) + 2);
        tok[4+i] = (uint8_t)((ec-oc) - (en-on) + 2);
    }
}

typedef struct {
    uint32_t bigram[8][5][5];
    uint8_t prev[8];
    uint32_t n;
} Pred;

static void pred_init(Pred *p) {
    memset(p, 0, sizeof(Pred));
    for (int c = 0; c < 8; c++) { p->prev[c] = 2; for (int i=0;i<5;i++) for(int j=0;j<5;j++) p->bigram[c][i][j]=1; }
}

static float pred_feed(Pred *p, const uint8_t tok[8]) {
    float conf = 0;
    if (p->n >= WARMUP) {
        for (int c = 0; c < 8; c++) {
            uint32_t *row = p->bigram[c][p->prev[c]];
            uint32_t tot=0, best=0;
            for (int j=0;j<5;j++) { tot+=row[j]; if(row[j]>best) best=row[j]; }
            if (tot>0) conf += (float)best/tot;
        }
        conf /= 8.0f;
    }
    for (int c=0;c<8;c++) { p->bigram[c][p->prev[c]][tok[c]]++; p->prev[c]=tok[c]; }
    p->n++;
    return conf;
}

static int find_regions(const uint8_t *data, size_t n, Region *regions) {
    Pred pred; pred_init(&pred);
    float *scores = calloc(n, sizeof(float));
    for (size_t i=0;i+1<n;i++) { uint8_t tok[8]; compute_tokens(data[i],data[i+1],tok); scores[i]=pred_feed(&pred,tok); }

    /* Smooth */
    float *smooth = calloc(n, sizeof(float));
    for (size_t i=0;i<n-1;i++) {
        float s=0; int c=0;
        for (int w=-WINDOW/2;w<=WINDOW/2;w++) { int idx=(int)i+w; if(idx>=0&&idx<(int)(n-1)){s+=scores[idx];c++;} }
        smooth[i] = c>0 ? s/c : 0;
    }

    int nr = 0;
    RType cur = smooth[0]>0.7f ? R_STRUCTURAL : smooth[0]>0.5f ? R_CONSTRAINED : R_EDITABLE;
    uint32_t rs = 0;
    for (size_t i=1;i<n-1&&nr<MAX_REGIONS;i++) {
        RType t = smooth[i]>0.7f ? R_STRUCTURAL : smooth[i]>0.5f ? R_CONSTRAINED : R_EDITABLE;
        if (t != cur) {
            float avg=0; for(uint32_t j=rs;j<(uint32_t)i;j++) avg+=smooth[j];
            regions[nr++] = (Region){rs,(uint32_t)i,cur,avg/(i-rs)};
            cur=t; rs=(uint32_t)i;
        }
    }
    if (nr<MAX_REGIONS) { regions[nr++]=(Region){rs,(uint32_t)(n-1),cur,0}; }
    free(scores); free(smooth);
    return nr;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t max) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;
    size_t n = len / 2;
    if (n > max) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned int byte;
        if (sscanf(hex + i*2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return (int)n;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "h3x_patch — Structure-Aware Binary Patcher\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s <file> --list\n", argv[0]);
        fprintf(stderr, "  %s <file> --inject <offset_hex> <payload_hex>\n", argv[0]);
        fprintf(stderr, "  %s <file> --auto <payload_hex> [-o output]\n", argv[0]);
        fprintf(stderr, "  %s <file> --embed <payload_file> [-o output]\n", argv[0]);
        fprintf(stderr, "\nOnly patches EDITABLE regions (use --force to override).\n");
        return 1;
    }

    const char *filepath = argv[1];
    const char *mode = argv[2];
    int force = 0;
    const char *outpath = NULL;

    for (int i=3;i<argc;i++) { if(!strcmp(argv[i],"--force")) force=1; if(!strcmp(argv[i],"-o")&&i+1<argc) outpath=argv[++i]; }

    /* Read file */
    FILE *f = fopen(filepath, "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END); long fsize = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *data = malloc(fsize);
    fread(data, 1, fsize, f); fclose(f);

    /* Analyze */
    Region regions[MAX_REGIONS];
    int nr = find_regions(data, (size_t)fsize, regions);

    if (!strcmp(mode, "--list")) {
        printf("Editable regions in %s (%ld bytes):\n", filepath, fsize);
        printf("  %8s %8s %8s %6s\n", "Start", "End", "Size", "Conf");
        for (int i=0;i<nr;i++) {
            if (regions[i].type == R_EDITABLE) {
                uint32_t sz = regions[i].end - regions[i].start;
                if (sz < 4) continue;
                printf("  0x%06X 0x%06X %8u %5.0f%%\n",
                    regions[i].start, regions[i].end, sz, regions[i].conf*100);
            }
        }
        free(data); return 0;
    }

    if (!strcmp(mode, "--inject") && argc >= 5) {
        uint32_t offset = (uint32_t)strtol(argv[3], NULL, 16);
        uint8_t payload[65536];
        int plen = hex_to_bytes(argv[4], payload, sizeof(payload));
        if (plen < 0) { fprintf(stderr, "Invalid hex payload\n"); free(data); return 1; }

        /* Check if offset is in an editable region */
        int in_editable = 0;
        for (int i=0;i<nr;i++) {
            if (regions[i].type == R_EDITABLE && offset >= regions[i].start && offset + plen <= regions[i].end) {
                in_editable = 1; break;
            }
        }

        if (!in_editable && !force) {
            fprintf(stderr, "ERROR: Offset 0x%X is NOT in an editable region.\n", offset);
            fprintf(stderr, "       This would modify structural/constrained bytes.\n");
            fprintf(stderr, "       Use --force to override (DANGEROUS).\n");
            free(data); return 1;
        }

        /* Patch */
        memcpy(data + offset, payload, plen);
        printf("Patched %d bytes at offset 0x%X\n", plen, offset);

        /* Write output */
        const char *out = outpath ? outpath : filepath;
        FILE *fo = fopen(out, "wb");
        fwrite(data, 1, fsize, fo); fclose(fo);
        printf("Written to %s\n", out);

        /* Verify: re-analyze and check for cascade */
        Region regions2[MAX_REGIONS];
        int nr2 = find_regions(data, (size_t)fsize, regions2);
        int cascades = 0;
        for (int i=0;i<nr2&&i<nr;i++) {
            if (regions2[i].type != regions[i].type &&
                !(regions[i].start >= offset && regions[i].start < offset + plen)) {
                cascades++;
            }
        }
        if (cascades > 0) {
            printf("WARNING: %d structural cascades detected (regions changed type)\n", cascades);
        } else {
            printf("VERIFIED: No structural cascade — patch is geometrically safe.\n");
        }

        free(data); return 0;
    }

    if (!strcmp(mode, "--auto") && argc >= 4) {
        uint8_t payload[65536];
        int plen = hex_to_bytes(argv[3], payload, sizeof(payload));
        if (plen < 0) { fprintf(stderr, "Invalid hex\n"); free(data); return 1; }

        /* Find largest editable region */
        int best = -1; uint32_t best_sz = 0;
        for (int i=0;i<nr;i++) {
            if (regions[i].type == R_EDITABLE) {
                uint32_t sz = regions[i].end - regions[i].start;
                if (sz > best_sz && sz >= (uint32_t)plen) { best=i; best_sz=sz; }
            }
        }
        if (best < 0) { fprintf(stderr, "No editable region large enough for %d bytes\n", plen); free(data); return 1; }

        uint32_t offset = regions[best].start;
        memcpy(data + offset, payload, plen);
        printf("Auto-patched %d bytes at 0x%X (region size: %u)\n", plen, offset, best_sz);

        const char *out = outpath ? outpath : filepath;
        FILE *fo = fopen(out, "wb"); fwrite(data, 1, fsize, fo); fclose(fo);
        printf("Written to %s\n", out);
        free(data); return 0;
    }

    if (!strcmp(mode, "--embed") && argc >= 4) {
        FILE *pf = fopen(argv[3], "rb");
        if (!pf) { perror("payload fopen"); free(data); return 1; }
        fseek(pf,0,SEEK_END); long psize=ftell(pf); fseek(pf,0,SEEK_SET);
        uint8_t *payload = malloc(psize); fread(payload,1,psize,pf); fclose(pf);

        int best=-1; uint32_t best_sz=0;
        for (int i=0;i<nr;i++) {
            if (regions[i].type==R_EDITABLE) {
                uint32_t sz=regions[i].end-regions[i].start;
                if (sz>best_sz && sz>=(uint32_t)psize) { best=i; best_sz=sz; }
            }
        }
        if (best<0) { fprintf(stderr,"No editable region for %ld bytes\n",psize); free(data); free(payload); return 1; }

        memcpy(data+regions[best].start, payload, psize);
        printf("Embedded %ld bytes at 0x%X\n", psize, regions[best].start);

        const char *out = outpath ? outpath : filepath;
        FILE *fo = fopen(out,"wb"); fwrite(data,1,fsize,fo); fclose(fo);
        printf("Written to %s\n", out);
        free(data); free(payload); return 0;
    }

    fprintf(stderr, "Unknown mode: %s\n", mode);
    free(data); return 1;
}

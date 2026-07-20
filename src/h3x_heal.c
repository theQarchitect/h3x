/*
 * h3x_heal — Cascade Correction via Predictive State Restoration
 * ================================================================
 * Author: Derek Hinch
 *
 * When you modify bytes in an editable region, the downstream transition
 * state diverges from the original — causing structural cascades detected
 * by h3x_lucky. This tool HEALS those cascades by propagating minimal
 * corrections that restore the expected transition orbit.
 *
 * Theory:
 *   The bigram predictor learns P(token_t | token_{t-1}) from the original.
 *   After a patch at position P, the transition at P changes, which shifts
 *   the bigram context for P+1, P+2, etc. — causing a cascade.
 *
 *   h3x_heal computes the "correction wavefront":
 *   For each position after the patch, it finds the byte value that would
 *   produce the SAME transition token as the original file did.
 *   This is possible because the 5-state space is small — we can solve
 *   for the corrective byte exactly.
 *
 * Algorithm:
 *   1. Analyze original file → store all transition tokens
 *   2. Apply user's patch
 *   3. Walk forward from patch site
 *   4. At each position: if current transition ≠ original transition,
 *      find byte B' such that transition(patched[i-1], B') = original_token[i-1]
 *   5. If B' exists AND position is in an editable region → apply correction
 *   6. Stop when transitions re-converge (or hit a structural boundary)
 *
 * The key insight: because there are only 5 possible transition values per
 * coefficient, and the Haar transform is invertible, we can SOLVE for the
 * corrective byte exactly. No approximation needed.
 *
 * Usage:
 *   h3x_heal <original> <patched> -o <healed>
 *   h3x_heal <file> --patch <offset> <hex> -o <output>
 *
 * Build:
 *   cc -O3 -o h3x_heal h3x_heal.c -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "../include/h3x_format.h"

#define WARMUP 200
#define WINDOW 32
#define MAX_HEAL_DISTANCE 4096  /* Max bytes to heal forward from patch */

/* ═══════════════════════════════════════════════════════════════════════════
 * Core: Solve for corrective byte
 *
 * Given: prev_byte (the byte before position i in patched file)
 *        target_tokens[8] (the transition tokens from the ORIGINAL file)
 * Find:  byte B such that transition(prev_byte, B) == target_tokens
 *
 * The Haar transform is:
 *   token_cA[k] = (bit_{2k}(prev) + bit_{2k+1}(prev))
 *              - (bit_{2k}(next) + bit_{2k+1}(next)) + 2
 *   token_cD[k] = (bit_{2k}(prev) - bit_{2k+1}(prev))
 *              - (bit_{2k}(next) - bit_{2k+1}(next)) + 2
 *
 * Solving for next bits:
 *   Let sp = bit_{2k}(prev) + bit_{2k+1}(prev)
 *   Let dp = bit_{2k}(prev) - bit_{2k+1}(prev)
 *   Target: sp - sn = target_cA - 2,  dp - dn = target_cD - 2
 *   So: sn = sp - (target_cA - 2),  dn = dp - (target_cD - 2)
 *   Then: bit_{2k}(next) = (sn + dn) / 2,  bit_{2k+1}(next) = (sn - dn) / 2
 *   These must be in {0, 1} for a valid byte.
 * ═══════════════════════════════════════════════════════════════════════════ */

static int solve_corrective_byte(uint8_t prev_byte, const uint8_t target_tokens[8], uint8_t *out_byte) {
    uint8_t result = 0;

    for (int k = 0; k < 4; k++) {
        int bit_even_p = (prev_byte >> (7 - 2*k)) & 1;
        int bit_odd_p  = (prev_byte >> (6 - 2*k)) & 1;

        int sp = bit_even_p + bit_odd_p;  /* sum of prev pair */
        int dp = bit_even_p - bit_odd_p;  /* diff of prev pair */

        int d_ca = (int)target_tokens[k] - 2;     /* ∈ {-2,-1,0,1,2} */
        int d_cd = (int)target_tokens[4+k] - 2;   /* ∈ {-2,-1,0,1,2} */

        /* Solve: sn = sp - d_ca,  dn = dp - d_cd */
        int sn = sp - d_ca;
        int dn = dp - d_cd;

        /* Recover bits: even = (sn + dn) / 2,  odd = (sn - dn) / 2 */
        int sum_bits = sn + dn;
        int diff_bits = sn - dn;

        if (sum_bits % 2 != 0 || diff_bits % 2 != 0) return 0; /* No valid byte */

        int bit_even_n = sum_bits / 2;
        int bit_odd_n  = diff_bits / 2;

        if (bit_even_n < 0 || bit_even_n > 1) return 0;
        if (bit_odd_n < 0 || bit_odd_n > 1) return 0;

        result |= (uint8_t)(bit_even_n << (7 - 2*k));
        result |= (uint8_t)(bit_odd_n << (6 - 2*k));
    }

    *out_byte = result;
    return 1; /* Success */
}

/* Compute transition tokens between two bytes */
static void compute_tokens(uint8_t a, uint8_t b, uint8_t tok[8]) {
    for (int i = 0; i < 4; i++) {
        int ec=(a>>(7-2*i))&1, oc=(a>>(6-2*i))&1;
        int en=(b>>(7-2*i))&1, on=(b>>(6-2*i))&1;
        tok[i]   = (uint8_t)((ec+oc)-(en+on)+2);
        tok[4+i] = (uint8_t)((ec-oc)-(en-on)+2);
    }
}

/* Region detection (simplified — just checks if position is editable) */
typedef struct { uint32_t bigram[8][5][5]; uint8_t prev[8]; uint32_t n; } Pred;
static void pred_init(Pred *p) {
    memset(p,0,sizeof(Pred)); for(int c=0;c<8;c++){p->prev[c]=2;for(int i=0;i<5;i++)for(int j=0;j<5;j++)p->bigram[c][i][j]=1;}
}
static float pred_feed(Pred *p, const uint8_t tok[8]) {
    float conf=0;
    if(p->n>=WARMUP){for(int c=0;c<8;c++){uint32_t*row=p->bigram[c][p->prev[c]];uint32_t tot=0,best=0;for(int j=0;j<5;j++){tot+=row[j];if(row[j]>best)best=row[j];}if(tot>0)conf+=(float)best/tot;}conf/=8.0f;}
    for(int c=0;c<8;c++){p->bigram[c][p->prev[c]][tok[c]]++;p->prev[c]=tok[c];} p->n++;
    return conf;
}

static int is_position_editable(const uint8_t *data, size_t n, uint32_t pos) {
    /* Quick local confidence check: if the area around pos has low confidence, it's editable */
    if (pos < WARMUP + WINDOW || pos + WINDOW >= n) return 1; /* Edge: assume editable */
    Pred pred; pred_init(&pred);
    /* Train on preceding data */
    uint32_t start = pos > 300 ? pos - 300 : 0;
    for (uint32_t i = start; i + 1 < pos; i++) {
        uint8_t tok[8]; compute_tokens(data[i], data[i+1], tok);
        pred_feed(&pred, tok);
    }
    /* Check confidence at pos */
    uint8_t tok[8]; compute_tokens(data[pos], data[pos+1], tok);
    float conf = pred_feed(&pred, tok);
    return conf < 0.65f; /* Below structural threshold = editable */
}

/* ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "h3x_heal — Cascade Correction via Predictive State Restoration\n\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s <original> <patched> -o <healed>\n", argv[0]);
        fprintf(stderr, "  %s <file> --patch <offset_hex> <payload_hex> -o <output>\n", argv[0]);
        fprintf(stderr, "\nHeals structural cascades by restoring the original transition orbit\n");
        fprintf(stderr, "in downstream positions, while preserving your payload at the patch site.\n");
        return 1;
    }

    const char *outpath = NULL;
    for (int i=1;i<argc;i++) if(!strcmp(argv[i],"-o")&&i+1<argc) outpath=argv[i+1];

    /* Mode 1: Diff-heal (given original + patched) */
    if (argc >= 4 && strcmp(argv[2], "--patch") != 0) {
        const char *orig_path = argv[1];
        const char *patched_path = argv[2];

        FILE *fo = fopen(orig_path, "rb");
        FILE *fp = fopen(patched_path, "rb");
        if (!fo || !fp) { perror("fopen"); return 1; }

        fseek(fo,0,SEEK_END); long fsize=ftell(fo); fseek(fo,0,SEEK_SET);
        uint8_t *orig = malloc(fsize); fread(orig,1,fsize,fo); fclose(fo);

        fseek(fp,0,SEEK_END); long psize=ftell(fp); fseek(fp,0,SEEK_SET);
        uint8_t *patched = malloc(psize); fread(patched,1,psize,fp); fclose(fp);

        if (fsize != psize) {
            fprintf(stderr, "Files must be same size for healing.\n");
            free(orig); free(patched); return 1;
        }

        size_t n = (size_t)fsize;

        /* Find first differing byte (the patch site) */
        uint32_t patch_start = 0;
        int found_diff = 0;
        for (size_t i = 0; i < n; i++) {
            if (orig[i] != patched[i]) { patch_start = (uint32_t)i; found_diff = 1; break; }
        }
        if (!found_diff) {
            printf("Files are identical — nothing to heal.\n");
            free(orig); free(patched); return 0;
        }

        /* Find end of patch (last differing byte in the patch cluster) */
        uint32_t patch_end = patch_start;
        for (size_t i = patch_start; i < n && i < patch_start + 1024; i++) {
            if (orig[i] != patched[i]) patch_end = (uint32_t)i;
        }
        patch_end++; /* Exclusive end */

        printf("h3x_heal: Healing cascade from patch at 0x%X-0x%X (%u bytes)\n",
               patch_start, patch_end, patch_end - patch_start);

        /* Compute original transition tokens for the healing zone */
        uint8_t *healed = malloc(n);
        memcpy(healed, patched, n); /* Start with patched data */

        uint32_t heal_start = patch_end;
        uint32_t heal_end = patch_end + MAX_HEAL_DISTANCE;
        if (heal_end >= n) heal_end = (uint32_t)(n - 1);

        int corrections = 0;
        int skipped_structural = 0;
        int converged_at = -1;

        for (uint32_t i = heal_start; i < heal_end; i++) {
            /* What was the original transition at this position? */
            uint8_t orig_tokens[8];
            compute_tokens(orig[i-1], orig[i], orig_tokens);

            /* What is the current transition (in the healed/patched data)? */
            uint8_t curr_tokens[8];
            compute_tokens(healed[i-1], healed[i], curr_tokens);

            /* Are they the same? */
            if (memcmp(orig_tokens, curr_tokens, 8) == 0) {
                /* Transitions match — cascade has converged! */
                if (converged_at < 0) converged_at = (int)i;
                /* Check if we have 8+ consecutive matches (stable convergence) */
                int stable = 1;
                for (uint32_t j = i; j < i + 8 && j < heal_end; j++) {
                    uint8_t ot[8], ct[8];
                    compute_tokens(orig[j-1], orig[j], ot);
                    compute_tokens(healed[j-1], healed[j], ct);
                    if (memcmp(ot, ct, 8) != 0) { stable = 0; break; }
                }
                if (stable) break; /* Done — orbit re-converged */
                continue;
            }

            converged_at = -1;

            /* Try to correct: find byte B' such that
             * transition(healed[i-1], B') == orig_tokens */
            uint8_t corrective_byte;
            if (solve_corrective_byte(healed[i-1], orig_tokens, &corrective_byte)) {
                /* Check if this position is editable (safe to modify) */
                if (is_position_editable(orig, n, i)) {
                    healed[i] = corrective_byte;
                    corrections++;
                } else {
                    skipped_structural++;
                }
            }
            /* If no valid corrective byte exists, leave as-is */
        }

        printf("  Healing zone: 0x%X - 0x%X (%u bytes scanned)\n",
               heal_start, heal_end, heal_end - heal_start);
        printf("  Corrections applied: %d\n", corrections);
        printf("  Skipped (structural): %d\n", skipped_structural);
        if (converged_at >= 0) {
            printf("  Orbit converged at: 0x%X (distance: %d bytes from patch)\n",
                   converged_at, converged_at - (int)patch_end);
        } else {
            printf("  Orbit did NOT converge within %d bytes\n", MAX_HEAL_DISTANCE);
        }

        /* Verify: compare fingerprints */
        printf("\n  Verification:\n");
        int remaining_diffs = 0;
        for (size_t i = heal_start; i + 1 < n && i < heal_end; i++) {
            uint8_t ot[8], ht[8];
            compute_tokens(orig[i], orig[i+1], ot);
            compute_tokens(healed[i], healed[i+1], ht);
            if (memcmp(ot, ht, 8) != 0) remaining_diffs++;
        }
        printf("  Remaining transition divergences: %d\n", remaining_diffs);
        printf("  Cascade eliminated: %s\n", remaining_diffs == 0 ? "YES" : "PARTIAL");

        /* Write output */
        if (outpath) {
            FILE *fout = fopen(outpath, "wb");
            fwrite(healed, 1, n, fout); fclose(fout);
            printf("  Healed output: %s\n", outpath);
        } else {
            printf("  (Use -o <path> to write healed output)\n");
        }

        free(orig); free(patched); free(healed);
        return 0;
    }

    /* Mode 2: Patch-and-heal in one shot */
    if (!strcmp(argv[2], "--patch") && argc >= 5) {
        const char *filepath = argv[1];
        uint32_t offset = (uint32_t)strtol(argv[3], NULL, 16);
        const char *hex_payload = argv[4];

        FILE *f = fopen(filepath, "rb");
        if (!f) { perror("fopen"); return 1; }
        fseek(f,0,SEEK_END); long fsize=ftell(f); fseek(f,0,SEEK_SET);
        uint8_t *orig = malloc(fsize); fread(orig,1,fsize,f); fclose(f);

        size_t n = (size_t)fsize;

        /* Parse hex payload */
        size_t hex_len = strlen(hex_payload);
        size_t payload_len = hex_len / 2;
        uint8_t *payload = malloc(payload_len);
        for (size_t i = 0; i < payload_len; i++) {
            unsigned int byte; sscanf(hex_payload + i*2, "%2x", &byte);
            payload[i] = (uint8_t)byte;
        }

        printf("h3x_heal: Patch + Heal at 0x%X (%zu bytes payload)\n", offset, payload_len);

        /* Create healed copy */
        uint8_t *healed = malloc(n);
        memcpy(healed, orig, n);
        memcpy(healed + offset, payload, payload_len);

        /* Heal forward */
        uint32_t heal_start = offset + (uint32_t)payload_len;
        uint32_t heal_end = heal_start + MAX_HEAL_DISTANCE;
        if (heal_end >= n) heal_end = (uint32_t)(n - 1);

        int corrections = 0;
        for (uint32_t i = heal_start; i < heal_end; i++) {
            uint8_t orig_tokens[8], curr_tokens[8];
            compute_tokens(orig[i-1], orig[i], orig_tokens);
            compute_tokens(healed[i-1], healed[i], curr_tokens);

            if (memcmp(orig_tokens, curr_tokens, 8) == 0) {
                /* Check for stable convergence */
                int stable = 1;
                for (uint32_t j = i; j < i+8 && j < heal_end; j++) {
                    uint8_t ot[8], ct[8];
                    compute_tokens(orig[j-1],orig[j],ot);
                    compute_tokens(healed[j-1],healed[j],ct);
                    if(memcmp(ot,ct,8)!=0){stable=0;break;}
                }
                if (stable) { printf("  Converged at 0x%X (+%u bytes)\n", i, i-heal_start); break; }
                continue;
            }

            uint8_t corrective;
            if (solve_corrective_byte(healed[i-1], orig_tokens, &corrective)) {
                healed[i] = corrective;
                corrections++;
            }
        }

        printf("  Corrections: %d bytes adjusted to restore transition orbit\n", corrections);

        if (outpath) {
            FILE *fout = fopen(outpath, "wb");
            fwrite(healed, 1, n, fout); fclose(fout);
            printf("  Output: %s\n", outpath);
        }

        free(orig); free(healed); free(payload);
        return 0;
    }

    fprintf(stderr, "Invalid arguments. Run with no args for usage.\n");
    return 1;
}

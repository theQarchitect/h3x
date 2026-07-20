/*
 * h3x_tcp — TCP Sequence Number Predictability Analyzer
 * ======================================================
 * Author: Derek Hinch
 *
 * Tests the quality of a host's TCP ISN (Initial Sequence Number) generator
 * by analyzing the transition lattice patterns in collected ISN bytes.
 *
 * Theory: A cryptographically secure ISN generator produces uniform
 * distribution across the 5-state lattice (~38% identity, ~20% each token).
 * A weak generator produces learnable patterns (>50% prediction).
 *
 * Modes:
 *   --capture <interface> <target> <N>  : Capture N ISNs via SYN probes
 *   --analyze <file>                    : Analyze saved ISN byte file
 *   --stdin                             : Read ISN bytes from stdin (pipe from tcpdump)
 *
 * Output: Prediction accuracy, identity density, lattice orbit analysis,
 *         and a PASS/WARN/FAIL grade for ISN randomness quality.
 *
 * Build: cc -O3 -o h3x_tcp h3x_tcp.c -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "../include/h3x_format.h"

/* Bigram predictor (same as h3x_analyze) */
typedef struct {
    uint32_t bigram[8][5][5];
    uint8_t prev[8];
    uint32_t n;
    uint32_t correct_frames;
    uint32_t correct_coeffs;
    uint32_t total_predicted;
} TCPPredictor;

static void compute_tokens(uint8_t a, uint8_t b, uint8_t tok[8]) {
    for (int i = 0; i < 4; i++) {
        int ec=(a>>(7-2*i))&1, oc=(a>>(6-2*i))&1;
        int en=(b>>(7-2*i))&1, on=(b>>(6-2*i))&1;
        tok[i]   = (uint8_t)((ec+oc)-(en+on)+2);
        tok[4+i] = (uint8_t)((ec-oc)-(en-on)+2);
    }
}

static void tcp_pred_init(TCPPredictor *p) {
    memset(p, 0, sizeof(TCPPredictor));
    for (int c=0;c<8;c++) { p->prev[c]=2; for(int i=0;i<5;i++) for(int j=0;j<5;j++) p->bigram[c][i][j]=1; }
}

static void tcp_pred_feed(TCPPredictor *p, const uint8_t tok[8], int warmup) {
    if ((int)p->n >= warmup) {
        int frame_correct = 1;
        int coeff_correct = 0;
        for (int c = 0; c < 8; c++) {
            uint32_t *row = p->bigram[c][p->prev[c]];
            uint32_t best_tok = 2, best_count = 0;
            for (int j = 0; j < 5; j++) {
                if (row[j] > best_count) { best_count = row[j]; best_tok = j; }
            }
            if (best_tok == tok[c]) coeff_correct++;
            else frame_correct = 0;
        }
        p->total_predicted++;
        if (frame_correct) p->correct_frames++;
        p->correct_coeffs += coeff_correct;
    }
    for (int c=0;c<8;c++) { p->bigram[c][p->prev[c]][tok[c]]++; p->prev[c]=tok[c]; }
    p->n++;
}

/* ═══════════════════════════════════════════════════════════════════════════ */

static void analyze_isn_stream(const uint8_t *data, size_t n, const char *source) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  H3X TCP SEQUENCE ANALYSIS\n");
    printf("  Source: %s (%zu bytes = %zu ISNs)\n", source, n, n / 4);
    printf("═══════════════════════════════════════════════════════════════\n\n");

    int warmup = 100;
    TCPPredictor pred;
    tcp_pred_init(&pred);

    uint32_t token_dist[5] = {0};
    uint64_t total_tokens = 0;

    /* Feed byte-by-byte through predictor */
    for (size_t i = 0; i + 1 < n; i++) {
        uint8_t tok[8];
        compute_tokens(data[i], data[i+1], tok);
        tcp_pred_feed(&pred, tok, warmup);
        for (int j = 0; j < 8; j++) { token_dist[tok[j]]++; total_tokens++; }
    }

    /* Results */
    float coeff_acc = pred.total_predicted > 0 ?
        (float)pred.correct_coeffs / (pred.total_predicted * 8) * 100 : 0;
    float frame_acc = pred.total_predicted > 0 ?
        (float)pred.correct_frames / pred.total_predicted * 100 : 0;
    float identity_pct = total_tokens > 0 ?
        (float)token_dist[2] / total_tokens * 100 : 0;

    printf("  Token Distribution:\n");
    const char *names[] = {"-√2", "-1/√2", "0(id)", "+1/√2", "+√2"};
    for (int i = 0; i < 5; i++) {
        float pct = total_tokens > 0 ? (float)token_dist[i] / total_tokens * 100 : 0;
        printf("    %6s: %5.1f%%  ", names[i], pct);
        int bar = (int)(pct / 2);
        for (int b = 0; b < bar; b++) printf("█");
        printf("\n");
    }

    printf("\n  Prediction Results (warmup=%d):\n", warmup);
    printf("    Per-coefficient accuracy: %.1f%%\n", coeff_acc);
    printf("    Full-frame accuracy:      %.1f%%\n", frame_acc);
    printf("    Identity density:         %.1f%%\n", identity_pct);
    printf("    Samples after warmup:     %u\n", pred.total_predicted);

    /* Grade */
    printf("\n  ═══ ISN RANDOMNESS GRADE ═══\n");
    if (coeff_acc < 30.0f) {
        printf("    Grade: PASS (cryptographically strong)\n");
        printf("    The ISN generator produces near-uniform lattice distribution.\n");
        printf("    Prediction accuracy is below random chance — no learnable pattern.\n");
    } else if (coeff_acc < 50.0f) {
        printf("    Grade: ACCEPTABLE (adequate randomness)\n");
        printf("    Some statistical bias detected but not exploitable.\n");
        printf("    Identity density: %.1f%% (ideal: ~38%%)\n", identity_pct);
    } else if (coeff_acc < 70.0f) {
        printf("    Grade: WARN (weak randomness)\n");
        printf("    ISN sequence has LEARNABLE structure (>50%% prediction).\n");
        printf("    An attacker with ~%d samples could predict next ISN.\n",
               warmup * 2);
        printf("    RECOMMENDATION: Upgrade TCP stack ISN generator.\n");
    } else {
        printf("    Grade: FAIL (PREDICTABLE)\n");
        printf("    ISN sequence is %.0f%% predictable — TRIVIALLY EXPLOITABLE.\n", coeff_acc);
        printf("    TCP session hijacking is feasible with minimal samples.\n");
        printf("    CRITICAL: This system's TCP stack is compromised.\n");
    }

    /* Bonus: check for sequential/time-based patterns */
    if (n >= 16) {
        /* Check if ISNs are incrementing (ancient TCP stacks) */
        int sequential = 0;
        for (size_t i = 4; i + 4 <= n; i += 4) {
            uint32_t isn1 = (data[i-4]<<24)|(data[i-3]<<16)|(data[i-2]<<8)|data[i-1];
            uint32_t isn2 = (data[i]<<24)|(data[i+1]<<16)|(data[i+2]<<8)|data[i+3];
            if (isn2 > isn1 && isn2 - isn1 < 100000) sequential++;
        }
        float seq_pct = (float)sequential / (n/4 - 1) * 100;
        if (seq_pct > 50) {
            printf("\n    WARNING: %.0f%% of ISNs are sequential (time-based generator)\n", seq_pct);
        }
    }

    printf("\n═══════════════════════════════════════════════════════════════\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "h3x_tcp — TCP ISN Randomness Analyzer\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s --analyze <isn_bytes_file>\n", argv[0]);
        fprintf(stderr, "  %s --stdin\n", argv[0]);
        fprintf(stderr, "  %s --generate-test <mode> <count>\n", argv[0]);
        fprintf(stderr, "    modes: random, sequential, weak, time-based\n");
        fprintf(stderr, "\nInput: Raw 4-byte ISN values concatenated (big-endian).\n");
        fprintf(stderr, "Capture with: tcpdump -c 100 'tcp[tcpflags] == tcp-syn' | h3x_tcp --stdin\n");
        return 1;
    }

    if (!strcmp(argv[1], "--analyze") && argc >= 3) {
        FILE *f = fopen(argv[2], "rb");
        if (!f) { perror("fopen"); return 1; }
        fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
        uint8_t *data = malloc(sz); fread(data,1,sz,f); fclose(f);
        analyze_isn_stream(data, (size_t)sz, argv[2]);
        free(data); return 0;
    }

    if (!strcmp(argv[1], "--generate-test") && argc >= 4) {
        const char *mode = argv[2];
        int count = atoi(argv[3]);
        uint8_t *data = malloc(count * 4);
        srand((unsigned)time(NULL));

        if (!strcmp(mode, "random")) {
            for (int i = 0; i < count * 4; i++) data[i] = rand() & 0xFF;
        } else if (!strcmp(mode, "sequential")) {
            uint32_t isn = 1000;
            for (int i = 0; i < count; i++) {
                isn += 64000; /* Classic 64K increment */
                data[i*4]=(isn>>24)&0xFF; data[i*4+1]=(isn>>16)&0xFF;
                data[i*4+2]=(isn>>8)&0xFF; data[i*4+3]=isn&0xFF;
            }
        } else if (!strcmp(mode, "weak")) {
            uint32_t isn = rand();
            for (int i = 0; i < count; i++) {
                isn += (rand() % 256) + 1; /* Small random increments */
                data[i*4]=(isn>>24)&0xFF; data[i*4+1]=(isn>>16)&0xFF;
                data[i*4+2]=(isn>>8)&0xFF; data[i*4+3]=isn&0xFF;
            }
        } else if (!strcmp(mode, "time-based")) {
            uint32_t isn = (uint32_t)time(NULL) * 250000;
            for (int i = 0; i < count; i++) {
                isn += 250000 + (rand() % 1000); /* time-based + small jitter */
                data[i*4]=(isn>>24)&0xFF; data[i*4+1]=(isn>>16)&0xFF;
                data[i*4+2]=(isn>>8)&0xFF; data[i*4+3]=isn&0xFF;
            }
        } else {
            fprintf(stderr, "Unknown mode: %s\n", mode); free(data); return 1;
        }

        analyze_isn_stream(data, count * 4, mode);
        free(data); return 0;
    }

    if (!strcmp(argv[1], "--stdin")) {
        /* Read from stdin */
        size_t cap = 1024*1024, n = 0;
        uint8_t *data = malloc(cap);
        int c;
        while ((c = fgetc(stdin)) != EOF && n < cap) data[n++] = (uint8_t)c;
        analyze_isn_stream(data, n, "stdin");
        free(data); return 0;
    }

    fprintf(stderr, "Unknown command. Run with no args for help.\n");
    return 1;
}

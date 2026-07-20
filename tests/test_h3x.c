/*
 * H3X Format — Verification Test
 * Validates lossless encode/decode roundtrip per HWT-CS spec.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/h3x_format.h"

static int test_lut_roundtrip(void) {
    printf("Test 1: LUT Forward/Inverse Roundtrip (all 256 bytes)...\n");
    h3x_init_lut();

    int failures = 0;
    for (int b = 0; b < 256; b++) {
        H3X_WaveletFrame frame;
        h3x_byte_to_frame((uint8_t)b, &frame);
        uint8_t recovered = h3x_frame_to_byte(&frame);
        if (recovered != (uint8_t)b) {
            printf("  FAIL: byte %d → frame → %d\n", b, recovered);
            failures++;
        }
    }
    printf("  %s (%d/256 passed)\n", failures == 0 ? "PASS" : "FAIL", 256 - failures);
    return failures;
}

static int test_transition_exact(void) {
    printf("Test 2: Transition values are exact eigen-states...\n");
    h3x_init_lut();

    int failures = 0;
    /* Test all 256×256 byte pairs */
    for (int a = 0; a < 256; a++) {
        for (int b = 0; b < 256; b++) {
            H3X_WaveletFrame fa, fb;
            h3x_byte_to_frame((uint8_t)a, &fa);
            h3x_byte_to_frame((uint8_t)b, &fb);

            H3X_TransitionFrame trans;
            h3x_compute_transition(&fa, &fb, &trans);

            /* Verify all tokens are in [0,4] */
            for (int i = 0; i < H3X_COEFFS_PER_BYTE; i++) {
                if (trans.tokens[i] > 4) {
                    if (failures < 5) {
                        printf("  FAIL: (%d→%d) token[%d]=%d (>4)\n",
                               a, b, i, trans.tokens[i]);
                    }
                    failures++;
                }
            }

            /* Verify reconstruction */
            H3X_WaveletFrame fb_recovered;
            h3x_apply_transition(&fa, &trans, &fb_recovered);
            uint8_t b_recovered = h3x_frame_to_byte(&fb_recovered);
            if (b_recovered != (uint8_t)b) {
                if (failures < 5) {
                    printf("  FAIL: (%d→%d) reconstructed as %d\n", a, b, b_recovered);
                }
                failures++;
            }
        }
    }
    printf("  %s (%d failures in 65536 pairs)\n",
           failures == 0 ? "PASS" : "FAIL", failures);
    return failures;
}

static int test_full_pipeline(void) {
    printf("Test 3: Full H3X Encode/Decode Pipeline...\n");

    /* Test data: sequential bytes (simulates tensor stream) */
    uint8_t test_data[] = {64, 128, 200, 15, 0, 255, 128, 64, 32, 16};
    size_t n = sizeof(test_data);

    size_t comp_max = n * 10;
    uint8_t *compressed = (uint8_t *)malloc(comp_max);
    size_t comp_len = 0;

    int ret = h3x_encode(test_data, n, compressed, &comp_len);
    if (ret != 0) {
        printf("  FAIL: encode returned %d\n", ret);
        free(compressed);
        return 1;
    }

    printf("  Encoded: %zu bytes → %zu bytes (%.2fx)\n",
           n, comp_len, (float)n / (float)comp_len);

    /* Decode */
    uint8_t *decoded = (uint8_t *)malloc(n + 16);
    size_t dec_len = 0;

    ret = h3x_decode(compressed, comp_len, decoded, &dec_len);
    if (ret != 0) {
        printf("  FAIL: decode returned %d\n", ret);
        free(compressed); free(decoded);
        return 1;
    }

    /* Verify lossless */
    int match = (dec_len == n && memcmp(test_data, decoded, n) == 0);
    printf("  Decoded: %zu bytes, lossless=%s\n", dec_len, match ? "YES" : "NO");

    if (!match) {
        printf("  Original:     ");
        for (size_t i = 0; i < n; i++) printf("%3d ", test_data[i]);
        printf("\n  Reconstructed:");
        for (size_t i = 0; i < dec_len; i++) printf("%3d ", decoded[i]);
        printf("\n");
    }

    free(compressed);
    free(decoded);
    return match ? 0 : 1;
}

static int test_large_random(void) {
    printf("Test 4: Large Random Data (1MB)...\n");

    size_t n = 1024 * 1024;
    uint8_t *data = (uint8_t *)malloc(n);
    srand(42);
    for (size_t i = 0; i < n; i++) data[i] = (uint8_t)(rand() & 0xFF);

    size_t comp_max = n * 4;
    uint8_t *compressed = (uint8_t *)malloc(comp_max);
    size_t comp_len = 0;

    clock_t start = clock();
    int ret = h3x_encode(data, n, compressed, &comp_len);
    double enc_time = (double)(clock() - start) / CLOCKS_PER_SEC;

    if (ret != 0) {
        printf("  FAIL: encode returned %d\n", ret);
        free(data); free(compressed);
        return 1;
    }

    printf("  Encoded: %zu → %zu bytes (%.2fx, %.1f MB/s)\n",
           n, comp_len, (float)n / (float)comp_len,
           (n / 1e6) / enc_time);

    /* Decode */
    uint8_t *decoded = (uint8_t *)malloc(n + 16);
    size_t dec_len = 0;

    start = clock();
    ret = h3x_decode(compressed, comp_len, decoded, &dec_len);
    double dec_time = (double)(clock() - start) / CLOCKS_PER_SEC;

    if (ret != 0) {
        printf("  FAIL: decode returned %d\n", ret);
        free(data); free(compressed); free(decoded);
        return 1;
    }

    int match = (dec_len == n && memcmp(data, decoded, n) == 0);
    printf("  Decoded: %.1f MB/s, lossless=%s\n",
           (n / 1e6) / dec_time, match ? "YES" : "NO");

    free(data); free(compressed); free(decoded);
    return match ? 0 : 1;
}

int main(void) {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  H3X Format (Hamilton-Hilbert-Hinch) Verification Suite\n");
    printf("  HWT-CS-2026-REV1 Compliance Test\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    int total_failures = 0;
    total_failures += test_lut_roundtrip();
    total_failures += test_transition_exact();
    total_failures += test_full_pipeline();
    total_failures += test_large_random();

    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("  Result: %s (%d total failures)\n",
           total_failures == 0 ? "ALL PASS" : "SOME FAILURES", total_failures);
    printf("═══════════════════════════════════════════════════════════\n");

    return total_failures == 0 ? 0 : 1;
}

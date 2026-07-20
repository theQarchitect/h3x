/*
 * H3X NEON SIMD Kernels — ARM64 Accelerated Haar Wavelet Transitions
 * ===================================================================
 * Exploits NEON 128-bit vectors for batch processing:
 *   - 16 bytes → 16 frames in parallel (4 float32x4 lanes)
 *   - Transition computation: 4 frame pairs simultaneously
 *   - Token packing: 32 tokens → 12 bytes in one pass
 *
 * HWT-CS §2.1: Parallel Decomposition Isomorphism guarantees
 * each byte is independent — perfect for SIMD.
 *
 * QomputeAI 2024-2026
 */

#include "../include/h3x_format.h"
#include <string.h>

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * NEON Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

static const float32x4_t NEON_HALF_SQRT2 = {0.70710678f, 0.70710678f,
                                              0.70710678f, 0.70710678f};
static const float32x4_t NEON_SQRT2 = {1.41421356f, 1.41421356f,
                                         1.41421356f, 1.41421356f};
static const float32x4_t NEON_TWO = {2.0f, 2.0f, 2.0f, 2.0f};

/* ═══════════════════════════════════════════════════════════════════════════
 * Batch Haar Projection: 16 bytes → 16 WaveletFrames
 *
 * For each byte, extract 8 bits, compute 4 cA and 4 cD values.
 * NEON processes 4 bytes at a time (4 frames = 32 floats in parallel).
 * ═══════════════════════════════════════════════════════════════════════════ */

void h3x_neon_bytes_to_frames_16(const uint8_t *data, H3X_WaveletFrame *out_frames) {
    for (int block = 0; block < 4; block++) {
        /* Process 4 bytes in this block */
        int base = block * 4;

        /* Extract bits for 4 bytes, compute cA/cD for each pair position */
        for (int pair = 0; pair < 4; pair++) {
            /* Load even/odd bits from 4 bytes for this pair position */
            float even_bits[4], odd_bits[4];
            for (int b = 0; b < 4; b++) {
                uint8_t byte_val = data[base + b];
                even_bits[b] = (float)((byte_val >> (7 - 2*pair)) & 1);
                odd_bits[b]  = (float)((byte_val >> (6 - 2*pair)) & 1);
            }

            /* Load into NEON registers */
            float32x4_t v_even = vld1q_f32(even_bits);
            float32x4_t v_odd  = vld1q_f32(odd_bits);

            /* cA = (even + odd) * HALF_SQRT2 */
            float32x4_t sum = vaddq_f32(v_even, v_odd);
            float32x4_t ca = vmulq_f32(sum, NEON_HALF_SQRT2);

            /* cD = (even - odd) * HALF_SQRT2 */
            float32x4_t diff = vsubq_f32(v_even, v_odd);
            float32x4_t cd = vmulq_f32(diff, NEON_HALF_SQRT2);

            /* Store to frames */
            float ca_out[4], cd_out[4];
            vst1q_f32(ca_out, ca);
            vst1q_f32(cd_out, cd);

            for (int b = 0; b < 4; b++) {
                out_frames[base + b].coeff[0][pair] = ca_out[b];
                out_frames[base + b].coeff[1][pair] = cd_out[b];
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEON Transition Computation: 4 frame pairs simultaneously
 *
 * T = F_curr - F_next, then scale by √2 to get integer tokens.
 * Since all values ∈ S, multiplying by √2 gives exact {-2,-1,0,1,2}.
 * Add 2 to get token index [0..4].
 * ═══════════════════════════════════════════════════════════════════════════ */

void h3x_neon_compute_transitions_4(const H3X_WaveletFrame *f_curr,
                                     const H3X_WaveletFrame *f_next,
                                     H3X_TransitionFrame *out_trans) {
    for (int frame = 0; frame < 4; frame++) {
        /* Process cA row (4 values) */
        float32x4_t curr_ca = vld1q_f32(f_curr[frame].coeff[0]);
        float32x4_t next_ca = vld1q_f32(f_next[frame].coeff[0]);
        float32x4_t diff_ca = vsubq_f32(curr_ca, next_ca);

        /* Scale by √2 → exact integers {-2,-1,0,1,2} */
        float32x4_t scaled_ca = vmulq_f32(diff_ca, NEON_SQRT2);
        /* Round and add 2 → token indices {0,1,2,3,4} */
        int32x4_t int_ca = vcvtnq_s32_f32(scaled_ca);
        int32x4_t tok_ca = vaddq_s32(int_ca, vdupq_n_s32(2));

        /* Process cD row (4 values) */
        float32x4_t curr_cd = vld1q_f32(f_curr[frame].coeff[1]);
        float32x4_t next_cd = vld1q_f32(f_next[frame].coeff[1]);
        float32x4_t diff_cd = vsubq_f32(curr_cd, next_cd);

        float32x4_t scaled_cd = vmulq_f32(diff_cd, NEON_SQRT2);
        int32x4_t int_cd = vcvtnq_s32_f32(scaled_cd);
        int32x4_t tok_cd = vaddq_s32(int_cd, vdupq_n_s32(2));

        /* Store tokens (narrow int32 → uint8) */
        int32_t ca_vals[4], cd_vals[4];
        vst1q_s32(ca_vals, tok_ca);
        vst1q_s32(cd_vals, tok_cd);

        for (int i = 0; i < 4; i++) {
            out_trans[frame].tokens[i]     = (uint8_t)ca_vals[i];
            out_trans[frame].tokens[4 + i] = (uint8_t)cd_vals[i];
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEON 3-Bit Token Packing: 32 tokens → 12 bytes
 *
 * 32 tokens × 3 bits = 96 bits = 12 bytes.
 * Processes in groups of 8 tokens (24 bits = 3 bytes) using NEON shifts.
 * ═══════════════════════════════════════════════════════════════════════════ */

void h3x_neon_pack_tokens_32(const uint8_t *tokens, uint8_t *out_packed) {
    /* Process 8 tokens at a time → 3 bytes each, 4 groups = 12 bytes */
    for (int group = 0; group < 4; group++) {
        const uint8_t *t = &tokens[group * 8];
        uint8_t *out = &out_packed[group * 3];

        /* 8 tokens × 3 bits = 24 bits = 3 bytes
         * Byte 0: [t0:2][t0:1][t0:0][t1:2][t1:1][t1:0][t2:2][t2:1]
         * Byte 1: [t2:0][t3:2][t3:1][t3:0][t4:2][t4:1][t4:0][t5:2]
         * Byte 2: [t5:1][t5:0][t6:2][t6:1][t6:0][t7:2][t7:1][t7:0]
         */
        out[0] = (uint8_t)((t[0] << 5) | (t[1] << 2) | (t[2] >> 1));
        out[1] = (uint8_t)((t[2] << 7) | (t[3] << 4) | (t[4] << 1) | (t[5] >> 2));
        out[2] = (uint8_t)((t[5] << 6) | (t[6] << 3) | t[7]);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEON Batch Encode: full pipeline for large buffers
 * Uses NEON paths when data is aligned and large enough.
 * ═══════════════════════════════════════════════════════════════════════════ */

void h3x_neon_encode_batch(const uint8_t *data, size_t n_bytes,
                            uint8_t *token_stream, size_t *n_tokens_out) {
    extern void h3x_init_lut(void);
    h3x_init_lut();

    size_t n_transitions = n_bytes - 1;
    size_t tok_pos = 0;

    /* Process in blocks of 4 for NEON transition computation */
    H3X_WaveletFrame frames[5]; /* Need curr + next for each pair */

    size_t i = 0;
    while (i + 4 < n_bytes) {
        /* Load 5 consecutive frames (4 transitions) */
        for (int j = 0; j < 5; j++) {
            h3x_byte_to_frame(data[i + j], &frames[j]);
        }

        /* Compute 4 transitions using NEON */
        H3X_TransitionFrame trans[4];
        h3x_neon_compute_transitions_4(&frames[0], &frames[1], trans);

        /* Extract tokens */
        for (int j = 0; j < 4; j++) {
            memcpy(&token_stream[tok_pos], trans[j].tokens, H3X_COEFFS_PER_BYTE);
            tok_pos += H3X_COEFFS_PER_BYTE;
        }
        i += 4;
    }

    /* Handle remaining transitions (scalar fallback) */
    while (i < n_bytes - 1) {
        H3X_WaveletFrame fc, fn;
        h3x_byte_to_frame(data[i], &fc);
        h3x_byte_to_frame(data[i + 1], &fn);
        H3X_TransitionFrame trans;
        h3x_compute_transition(&fc, &fn, &trans);
        memcpy(&token_stream[tok_pos], trans.tokens, H3X_COEFFS_PER_BYTE);
        tok_pos += H3X_COEFFS_PER_BYTE;
        i++;
    }

    *n_tokens_out = tok_pos;
}

#endif /* __ARM_NEON || __aarch64__ */

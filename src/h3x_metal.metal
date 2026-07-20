/*
 * H3X Metal Compute Shaders — GPU-Accelerated Wavelet Transition Compression
 * ===========================================================================
 * HWT-CS §2.1: Parallel Decomposition Isomorphism — each byte is independent.
 * This means we can dispatch one thread per byte for the forward projection,
 * and one thread per transition for the token computation.
 *
 * Kernels:
 *   1. h3x_haar_forward:  byte[] → WaveletFrame[] (massively parallel)
 *   2. h3x_transition:    frame_pairs → token[] (one thread per pair)
 *   3. h3x_haar_inverse:  WaveletFrame[] → byte[] (massively parallel)
 *
 * The 5-state eigen-space means transition values, when scaled by √2,
 * are EXACTLY integers {-2,-1,0,1,2}. No approximation on GPU either.
 *
 * QomputeAI 2024-2026
 */

#include <metal_stdlib>
using namespace metal;

/* Constants matching h3x_format.h */
constant float HALF_SQRT2 = 0.70710678f;
constant float SQRT2      = 1.41421356f;

/* ═══════════════════════════════════════════════════════════════════════════
 * Kernel 1: Forward Haar Projection (HWT-CS §1.1)
 *
 * Each thread processes one byte → one WaveletFrame (2×4 floats = 8 floats).
 * Output layout: [cA0, cA1, cA2, cA3, cD0, cD1, cD2, cD3] per byte.
 * ═══════════════════════════════════════════════════════════════════════════ */

kernel void h3x_haar_forward(
    device const uint8_t *input_bytes [[buffer(0)]],
    device float *output_frames       [[buffer(1)]],
    uint tid [[thread_position_in_grid]]
) {
    uint8_t byte_val = input_bytes[tid];
    uint out_base = tid * 8;  /* 8 floats per frame */

    /* Extract 8 bits and compute 4 cA + 4 cD */
    for (int i = 0; i < 4; i++) {
        float b_even = float((byte_val >> (7 - 2*i)) & 1);
        float b_odd  = float((byte_val >> (6 - 2*i)) & 1);

        output_frames[out_base + i]     = (b_even + b_odd) * HALF_SQRT2;  /* cA_i */
        output_frames[out_base + 4 + i] = (b_even - b_odd) * HALF_SQRT2;  /* cD_i */
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Kernel 2: Transition Token Computation (HWT-CS §1.3)
 *
 * Each thread computes T = F_t - F_{t+1} for one adjacent pair.
 * Scales diff by √2 to get exact integer, adds 2 for token index.
 * Output: 8 tokens (uint8) per transition.
 * ═══════════════════════════════════════════════════════════════════════════ */

kernel void h3x_transition_compute(
    device const float *frames      [[buffer(0)]],  /* All WaveletFrames flat */
    device uint8_t *output_tokens   [[buffer(1)]],  /* 8 tokens per transition */
    constant uint &n_frames         [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= n_frames - 1) return;

    uint curr_base = tid * 8;
    uint next_base = (tid + 1) * 8;
    uint tok_base  = tid * 8;

    /* For each of 8 coefficients (4 cA + 4 cD): T = F_curr - F_next */
    for (int i = 0; i < 8; i++) {
        float diff = frames[curr_base + i] - frames[next_base + i];
        /* Per HWT-CS proof: diff * √2 is exactly an integer ∈ {-2,-1,0,1,2} */
        int scaled = int(round(diff * SQRT2));
        /* Map to token: add 2 → {0,1,2,3,4} */
        output_tokens[tok_base + i] = uint8_t(scaled + 2);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Kernel 3: Inverse Haar Projection (HWT-CS §1.4)
 *
 * Reconstructs bytes from WaveletFrames.
 * Each thread processes one frame → one byte.
 * ═══════════════════════════════════════════════════════════════════════════ */

kernel void h3x_haar_inverse(
    device const float *input_frames [[buffer(0)]],
    device uint8_t *output_bytes     [[buffer(1)]],
    uint tid [[thread_position_in_grid]]
) {
    uint base = tid * 8;
    uint8_t result = 0;

    for (int i = 0; i < 4; i++) {
        float ca = input_frames[base + i];
        float cd = input_frames[base + 4 + i];

        /* Inverse: b_even = (cA + cD) / √2, b_odd = (cA - cD) / √2 */
        int b_even = int(round((ca + cd) * HALF_SQRT2));
        int b_odd  = int(round((ca - cd) * HALF_SQRT2));

        b_even = clamp(b_even, 0, 1);
        b_odd  = clamp(b_odd, 0, 1);

        result |= uint8_t(b_even << (7 - 2*i));
        result |= uint8_t(b_odd  << (6 - 2*i));
    }

    output_bytes[tid] = result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Kernel 4: Apply Transitions (Sequential Reconstruction on GPU)
 *
 * Reconstructs frame[t+1] from frame[t] and token[t].
 * This kernel processes in chunks — each threadgroup handles a segment
 * with a known anchor frame, then reconstructs sequentially within.
 *
 * For large tensors, we split into independent segments at anchor points,
 * allowing parallel reconstruction of segments.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Eigen values indexed by token */
constant float EIGEN_VALUES[5] = {
    -1.41421356f,  /* token 0: -√2 */
    -0.70710678f,  /* token 1: -1/√2 */
     0.00000000f,  /* token 2:  0 */
     0.70710678f,  /* token 3: +1/√2 */
     1.41421356f   /* token 4: +√2 */
};

kernel void h3x_apply_transitions_segment(
    device const float *anchor_frames   [[buffer(0)]],  /* One frame per segment */
    device const uint8_t *tokens        [[buffer(1)]],  /* All tokens flat */
    device float *output_frames         [[buffer(2)]],  /* Reconstructed frames */
    constant uint &segment_size         [[buffer(3)]],  /* Frames per segment */
    constant uint &n_segments           [[buffer(4)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= n_segments) return;

    uint seg_start = tid * segment_size;
    uint anchor_base = tid * 8;

    /* Copy anchor frame to output */
    for (int i = 0; i < 8; i++) {
        output_frames[seg_start * 8 + i] = anchor_frames[anchor_base + i];
    }

    /* Sequential reconstruction within segment */
    for (uint t = 0; t < segment_size - 1; t++) {
        uint curr_idx = seg_start + t;
        uint next_idx = curr_idx + 1;
        uint tok_idx = curr_idx * 8;

        for (int i = 0; i < 8; i++) {
            float curr_val = output_frames[curr_idx * 8 + i];
            float t_val = EIGEN_VALUES[tokens[tok_idx + i]];
            /* F_{t+1} = F_t - T */
            output_frames[next_idx * 8 + i] = curr_val - t_val;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Kernel 5: RLE Sparse Identity Counter (preprocessing)
 *
 * Counts consecutive identity tokens (value 2) per position.
 * Output is used by CPU to construct RLE stream.
 * ═══════════════════════════════════════════════════════════════════════════ */

kernel void h3x_count_identity_runs(
    device const uint8_t *tokens    [[buffer(0)]],
    device uint32_t *run_lengths    [[buffer(1)]],  /* Run length starting at each pos */
    constant uint &n_tokens         [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= n_tokens) { return; }

    if (tokens[tid] != 2) {
        run_lengths[tid] = 0;
        return;
    }

    /* Count forward from this position */
    uint32_t count = 0;
    uint pos = tid;
    while (pos < n_tokens && tokens[pos] == 2 && count < 255) {
        count++;
        pos++;
    }
    run_lengths[tid] = count;
}

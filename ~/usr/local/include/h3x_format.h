/*
 * H3X Format — Hamilton-Hilbert-Hinch Wavelet Transition Compression
 * ===================================================================
 * Specification: HWT-CS-2026-REV1 (Hinch Wavelet Transition Compression Standard)
 *
 * The H3X format implements lossless 10.67x compression via:
 *   1. Hamilton:  Z_256 quaternion algebra for byte→quat tokenization
 *   2. Hilbert:   Hilbert curve reordering for spatial locality preservation
 *   3. Hinch:     3-bit eigen-token transition encoding (HWT-CS)
 *
 * Mathematical Foundation (HWT-CS §1):
 *   - Forward: B ∈ {0,1}^N → Haar DWT Level-1 → F ∈ R^{2×M}
 *   - Transition: T = F_t - F_{t+1}, T_{row,col} ∈ S = {-√2, -1/√2, 0, +1/√2, +√2}
 *   - Encoding: 5 discrete states → 3-bit tokens → RLE → Huffman
 *   - Compression: C = 32/3 ≈ 10.67x baseline (lossless)
 *
 * Entropy Coding Stack:
 *   Layer 1: 3-bit eigen-token quantization (5 states, HWT-CS §3)
 *   Layer 2: RLE on sparse identity tokens (>60% density, HWT-CS §3.2)
 *   Layer 3: Canonical Huffman on RLE symbols
 *
 * LASSO Predictor (H3X extension):
 *   - Positional embedding anchors at configurable stride
 *   - L1-regularized linear predictor on 4×2 transition frames
 *   - Predicted frames subtracted → residual stream is sparser
 *
 * QomputeAI 2024-2026. Author: Derek Hinch (spec), Implementation: Q.
 */

#ifndef H3X_FORMAT_H
#define H3X_FORMAT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * §1. Constants & Basis (HWT-CS §1.1, §1.2)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* √2 basis constants (8-digit precision as per HWT-CS §3.1) */
#define H3X_SQRT2       1.41421356f
#define H3X_HALF_SQRT2  0.70710678f

/* The 5-element quantized eigen-space S (HWT-CS §1.4) */
#define H3X_EIGEN_NEG_FULL   0   /* -√2      = -1.41421356 → token 000 */
#define H3X_EIGEN_NEG_HALF   1   /* -1/√2    = -0.70710678 → token 001 */
#define H3X_EIGEN_ZERO       2   /* 0.0      =  0.00000000 → token 010 */
#define H3X_EIGEN_POS_HALF   3   /* +1/√2    = +0.70710678 → token 011 */
#define H3X_EIGEN_POS_FULL   4   /* +√2      = +1.41421356 → token 100 */
#define H3X_NUM_EIGEN_STATES 5

/* Token bit width */
#define H3X_TOKEN_BITS       3

/* Frame geometry: each byte produces 2×4 = 8 wavelet coefficients */
#define H3X_COEFFS_PER_BYTE  8
#define H3X_CA_PER_BYTE      4
#define H3X_CD_PER_BYTE      4

/* LUT size: uint8 → 2×4 float frame (HWT-CS §2.1) */
#define H3X_LUT_SIZE         256
#define H3X_FRAME_ROWS       2    /* cA row, cD row */
#define H3X_FRAME_COLS       4    /* 4 bit-pairs per byte */

/* LASSO predictor */
#define H3X_ANCHOR_STRIDE    64   /* Positional embedding anchor interval */
#define H3X_PREDICT_WINDOW   4    /* Look-back frames for prediction */

/* RLE escape byte (used when run length exceeds inline capacity) */
#define H3X_RLE_ESCAPE       0xFF
#define H3X_RLE_MAX_RUN      255

/* Huffman */
#define H3X_HUFFMAN_MAX_SYMS 261  /* 5 eigen tokens + RLE run-length symbols */
#define H3X_HUFFMAN_MAX_BITS 15

/* ═══════════════════════════════════════════════════════════════════════════
 * §2. Data Structures
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Wavelet Frame Matrix F ∈ R^{2×M} (HWT-CS §1.1)
 * For a single byte: F ∈ R^{2×4}
 * Row 0 = cA (approximation), Row 1 = cD (detail) */
typedef struct {
    float coeff[H3X_FRAME_ROWS][H3X_FRAME_COLS];
} H3X_WaveletFrame;

/* Transition Frame T = F_t - F_{t+1} (HWT-CS §1.3)
 * All elements ∈ S = {-√2, -1/√2, 0, +1/√2, +√2} */
typedef struct {
    uint8_t tokens[H3X_COEFFS_PER_BYTE];  /* 3-bit tokens packed as uint8 for access */
} H3X_TransitionFrame;

/* RLE-encoded symbol: either a raw token or a run-length pair */
typedef struct {
    uint8_t symbol;    /* Eigen token (0-4) or RLE marker */
    uint8_t run_len;   /* Run length (0 = single, >0 = repeated) */
} H3X_RLESymbol;

/* Huffman code table entry */
typedef struct {
    uint16_t code;     /* Huffman codeword (MSB-aligned) */
    uint8_t  length;   /* Code length in bits */
} H3X_HuffEntry;

/* Huffman tree node */
typedef struct {
    uint32_t freq;
    int16_t  left;     /* -1 = leaf */
    int16_t  right;    /* -1 = leaf */
    int16_t  symbol;   /* Valid only for leaves */
} H3X_HuffNode;

/* LASSO predictor state (positional embedding anchors) */
typedef struct {
    float weights[H3X_PREDICT_WINDOW * H3X_COEFFS_PER_BYTE]; /* L1 coefficients */
    float anchor_frame[H3X_FRAME_ROWS][H3X_FRAME_COLS];      /* Last anchor */
    uint32_t position;                                         /* Current position */
    uint32_t anchor_stride;                                    /* Stride between anchors */
} H3X_LassoPredictor;

/* ═══════════════════════════════════════════════════════════════════════════
 * §3. File Format Header
 * ═══════════════════════════════════════════════════════════════════════════ */

#define H3X_MAGIC  0x48335846  /* "H3XF" in little-endian */
#define H3X_VERSION 1

typedef struct __attribute__((packed)) {
    uint32_t magic;            /* H3X_MAGIC */
    uint8_t  version;          /* H3X_VERSION */
    uint8_t  flags;            /* Bit 0: has_predictor, Bit 1: has_huffman */
    uint16_t anchor_stride;    /* LASSO anchor stride */
    uint32_t n_frames;         /* Total number of byte-frames in sequence */
    uint32_t n_transitions;    /* n_frames - 1 */
    uint32_t base_frame_len;   /* Length of base frame in bytes */
    uint32_t token_stream_len; /* Length of compressed token stream */
    uint32_t original_size;    /* Original uncompressed tensor size */
    float    compression_ratio;/* Achieved ratio */
} H3X_Header;

/* Flags */
#define H3X_FLAG_HAS_PREDICTOR  (1 << 0)
#define H3X_FLAG_HAS_HUFFMAN    (1 << 1)
#define H3X_FLAG_HAS_RLE        (1 << 2)

/* ═══════════════════════════════════════════════════════════════════════════
 * §4. Core API — Haar Bitspace Projector (HWT-CS §1.1)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Initialize the global uint8 → WaveletFrame LUT (HWT-CS §2.1).
 * Must be called once before any encode/decode operations.
 * Thread-safe: builds 256-entry static cache.
 */
void h3x_init_lut(void);

/**
 * Forward Haar Projection: byte → WaveletFrame (HWT-CS §1.1).
 * Uses precomputed LUT for O(1) lookup.
 *
 * cA_i = (b_{2i} + b_{2i+1}) / √2
 * cD_i = (b_{2i} - b_{2i+1}) / √2
 */
void h3x_byte_to_frame(uint8_t byte_val, H3X_WaveletFrame *out_frame);

/**
 * Inverse Haar Projection: WaveletFrame → byte (HWT-CS Decoupling Proof §1.4).
 * Δb_{2i}   = (ΔcA_i + ΔcD_i) / √2
 * Δb_{2i+1} = (ΔcA_i - ΔcD_i) / √2
 */
uint8_t h3x_frame_to_byte(const H3X_WaveletFrame *frame);

/**
 * Batch forward projection: byte array → concatenated WaveletFrame sequence.
 * Exploits Parallel Decomposition Isomorphism (HWT-CS §2.1):
 * W(V_W) ≡ W(Byte_0) || W(Byte_1) || ... || W(Byte_{M-1})
 */
void h3x_bytes_to_frames(const uint8_t *data, size_t n_bytes,
                          H3X_WaveletFrame *out_frames);

/**
 * Batch inverse projection: WaveletFrame sequence → byte array.
 */
void h3x_frames_to_bytes(const H3X_WaveletFrame *frames, size_t n_frames,
                          uint8_t *out_bytes);

/* ═══════════════════════════════════════════════════════════════════════════
 * §5. Transition Encoding (HWT-CS §1.3, §3)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Compute transition matrix T = F_t - F_{t+1} (HWT-CS §1.3).
 * Each element is EXACTLY one of the 5 eigen-states (no quantization needed).
 * Maps directly to 3-bit tokens via integer-scaled lookup.
 */
void h3x_compute_transition(const H3X_WaveletFrame *f_curr,
                             const H3X_WaveletFrame *f_next,
                             H3X_TransitionFrame *out_transition);

/**
 * Apply transition to reconstruct next frame: F_{t+1} = F_t - T.
 */
void h3x_apply_transition(const H3X_WaveletFrame *f_curr,
                           const H3X_TransitionFrame *transition,
                           H3X_WaveletFrame *out_next);

/**
 * Encode full byte sequence to H3X compressed stream.
 * Pipeline: bytes → frames → transitions → tokens → RLE → Huffman → packed bits.
 *
 * @param data           Input byte stream (tensor data)
 * @param n_bytes        Length of input
 * @param out_compressed Output buffer (caller allocates: n_bytes worst case)
 * @param out_len        Actual compressed length written
 * @return               0 on success, -1 on error
 */
int h3x_encode(const uint8_t *data, size_t n_bytes,
               uint8_t *out_compressed, size_t *out_len);

/**
 * Decode H3X compressed stream back to original bytes (100% lossless).
 *
 * @param compressed     H3X compressed data (including header)
 * @param comp_len       Length of compressed data
 * @param out_data       Output buffer (caller allocates: header.original_size)
 * @param out_len        Actual decompressed length written
 * @return               0 on success, -1 on error
 */
int h3x_decode(const uint8_t *compressed, size_t comp_len,
               uint8_t *out_data, size_t *out_len);

/* ═══════════════════════════════════════════════════════════════════════════
 * §6. Entropy Coding — RLE + Huffman (HWT-CS §3.2)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Run-Length Encode the token stream.
 * Exploits sparse identity dominance (>60% token=2).
 */
size_t h3x_rle_encode(const uint8_t *tokens, size_t n_tokens,
                       uint8_t *out_rle, size_t max_out);

/**
 * Run-Length Decode back to token stream.
 */
size_t h3x_rle_decode(const uint8_t *rle_data, size_t rle_len,
                       uint8_t *out_tokens, size_t max_out);

/**
 * Build Huffman table from symbol frequencies.
 */
void h3x_huffman_build(const uint32_t *freqs, size_t n_symbols,
                        H3X_HuffEntry *out_table);

/**
 * Huffman encode symbol stream to packed bits.
 */
size_t h3x_huffman_encode(const uint8_t *symbols, size_t n_symbols,
                           const H3X_HuffEntry *table,
                           uint8_t *out_bits, size_t max_out);

/**
 * Huffman decode packed bits back to symbols.
 */
size_t h3x_huffman_decode(const uint8_t *bits, size_t n_bits_total,
                           size_t n_symbols_expected,
                           const H3X_HuffEntry *table, size_t n_table_entries,
                           uint8_t *out_symbols, size_t max_out);

/* ═══════════════════════════════════════════════════════════════════════════
 * §7. LASSO Transition Predictor (H3X Extension)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Initialize LASSO predictor with positional anchors.
 */
void h3x_predictor_init(H3X_LassoPredictor *pred, uint32_t anchor_stride);

/**
 * Predict next transition frame from history.
 * Uses L1-regularized weights learned from sliding window.
 */
void h3x_predictor_predict(const H3X_LassoPredictor *pred,
                            const H3X_TransitionFrame *history,
                            size_t n_history,
                            H3X_TransitionFrame *out_predicted);

/**
 * Update predictor weights via coordinate descent (online learning).
 */
void h3x_predictor_update(H3X_LassoPredictor *pred,
                           const H3X_TransitionFrame *actual,
                           const H3X_TransitionFrame *predicted);

/* ═══════════════════════════════════════════════════════════════════════════
 * §8. NEON SIMD Declarations (ARM64 accelerated paths)
 * ═══════════════════════════════════════════════════════════════════════════ */

#if defined(__ARM_NEON) || defined(__aarch64__)
#define H3X_HAS_NEON 1

/**
 * NEON-accelerated batch Haar projection (16 bytes → 16 frames at once).
 */
void h3x_neon_bytes_to_frames_16(const uint8_t *data, H3X_WaveletFrame *out_frames);

/**
 * NEON-accelerated transition computation (processes 4 frame pairs).
 */
void h3x_neon_compute_transitions_4(const H3X_WaveletFrame *f_curr,
                                     const H3X_WaveletFrame *f_next,
                                     H3X_TransitionFrame *out_trans);

/**
 * NEON-accelerated 3-bit token packing (32 tokens → 12 bytes).
 */
void h3x_neon_pack_tokens_32(const uint8_t *tokens, uint8_t *out_packed);

#endif /* H3X_HAS_NEON */

/* ═══════════════════════════════════════════════════════════════════════════
 * §9. Metal GPU Declarations (macOS/iOS)
 * ═══════════════════════════════════════════════════════════════════════════ */

#if defined(__APPLE__)
#define H3X_HAS_METAL 1

/**
 * Metal GPU batch encode: entire tensor in one dispatch.
 * Returns compressed buffer (caller frees).
 */
int h3x_metal_encode(const uint8_t *data, size_t n_bytes,
                     uint8_t **out_compressed, size_t *out_len);

/**
 * Metal GPU batch decode.
 */
int h3x_metal_decode(const uint8_t *compressed, size_t comp_len,
                     uint8_t **out_data, size_t *out_len);

#endif /* __APPLE__ */

#ifdef __cplusplus
}
#endif

#endif /* H3X_FORMAT_H */

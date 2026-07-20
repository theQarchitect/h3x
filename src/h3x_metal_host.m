/*
 * H3X Metal Host — Objective-C bridge for Metal GPU compute
 * ===========================================================
 * Manages Metal device, command queue, pipeline states, and buffer
 * allocation for the H3X wavelet transition compression kernels.
 *
 * Usage:
 *   h3x_metal_init();
 *   h3x_metal_encode(data, n_bytes, &out, &out_len);
 *   h3x_metal_decode(compressed, comp_len, &out, &out_len);
 *   h3x_metal_cleanup();
 *
 * QomputeAI 2024-2026
 */

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include "../include/h3x_format.h"
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Metal State
 * ═══════════════════════════════════════════════════════════════════════════ */

static id<MTLDevice> g_device = nil;
static id<MTLCommandQueue> g_queue = nil;
static id<MTLLibrary> g_library = nil;
static id<MTLComputePipelineState> g_haar_forward_pso = nil;
static id<MTLComputePipelineState> g_transition_pso = nil;
static id<MTLComputePipelineState> g_haar_inverse_pso = nil;
static id<MTLComputePipelineState> g_apply_trans_pso = nil;
static int g_metal_initialized = 0;

/* ═══════════════════════════════════════════════════════════════════════════
 * Initialization
 * ═══════════════════════════════════════════════════════════════════════════ */

static int h3x_metal_init(void) {
    if (g_metal_initialized) return 0;

    @autoreleasepool {
        g_device = MTLCreateSystemDefaultDevice();
        if (!g_device) {
            fprintf(stderr, "[H3X Metal] No Metal device available\n");
            return -1;
        }

        g_queue = [g_device newCommandQueue];

        /* Load shader library from .metallib or source */
        NSError *error = nil;
        NSString *path = [[NSBundle mainBundle] pathForResource:@"h3x_metal"
                                                        ofType:@"metallib"];
        if (path) {
            NSURL *url = [NSURL fileURLWithPath:path];
            g_library = [g_device newLibraryWithURL:url error:&error];
        }

        if (!g_library) {
            /* Try compiling from source at runtime */
            NSString *srcPath = [NSString stringWithFormat:@"%s/h3x_metal.metal",
                                 __FILE__]; /* Same directory */
            /* Fallback: look in current directory */
            NSString *cwd = [[NSFileManager defaultManager] currentDirectoryPath];
            NSString *metalSrc = [NSString stringWithContentsOfFile:
                [cwd stringByAppendingPathComponent:@"h3x_metal.metal"]
                encoding:NSUTF8StringEncoding error:&error];

            if (metalSrc) {
                MTLCompileOptions *opts = [[MTLCompileOptions alloc] init];
                opts.fastMathEnabled = YES;
                g_library = [g_device newLibraryWithSource:metalSrc
                                                  options:opts error:&error];
            }
        }

        if (!g_library) {
            fprintf(stderr, "[H3X Metal] Failed to load shaders: %s\n",
                    [[error localizedDescription] UTF8String]);
            return -1;
        }

        /* Create pipeline states */
        id<MTLFunction> fn;

        fn = [g_library newFunctionWithName:@"h3x_haar_forward"];
        g_haar_forward_pso = [g_device newComputePipelineStateWithFunction:fn error:&error];

        fn = [g_library newFunctionWithName:@"h3x_transition_compute"];
        g_transition_pso = [g_device newComputePipelineStateWithFunction:fn error:&error];

        fn = [g_library newFunctionWithName:@"h3x_haar_inverse"];
        g_haar_inverse_pso = [g_device newComputePipelineStateWithFunction:fn error:&error];

        fn = [g_library newFunctionWithName:@"h3x_apply_transitions_segment"];
        g_apply_trans_pso = [g_device newComputePipelineStateWithFunction:fn error:&error];

        if (!g_haar_forward_pso || !g_transition_pso || !g_haar_inverse_pso) {
            fprintf(stderr, "[H3X Metal] Pipeline creation failed\n");
            return -1;
        }

        g_metal_initialized = 1;
        fprintf(stderr, "[H3X Metal] Initialized: %s\n",
                [[g_device name] UTF8String]);
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Metal Encode: Full GPU Pipeline
 *
 * 1. Upload bytes to GPU
 * 2. Dispatch h3x_haar_forward (one thread per byte)
 * 3. Dispatch h3x_transition_compute (one thread per adjacent pair)
 * 4. Read back tokens to CPU
 * 5. CPU: RLE + Huffman (sequential, small output)
 * ═══════════════════════════════════════════════════════════════════════════ */

int h3x_metal_encode(const uint8_t *data, size_t n_bytes,
                     uint8_t **out_compressed, size_t *out_len) {
    if (h3x_metal_init() != 0) return -1;

    @autoreleasepool {
        /* Allocate Metal buffers */
        id<MTLBuffer> buf_input = [g_device newBufferWithBytes:data
                                                       length:n_bytes
                                                      options:MTLResourceStorageModeShared];

        size_t frames_size = n_bytes * 8 * sizeof(float);
        id<MTLBuffer> buf_frames = [g_device newBufferWithLength:frames_size
                                                        options:MTLResourceStorageModeShared];

        size_t tokens_size = (n_bytes - 1) * 8;
        id<MTLBuffer> buf_tokens = [g_device newBufferWithLength:tokens_size
                                                        options:MTLResourceStorageModeShared];

        uint32_t n_frames_val = (uint32_t)n_bytes;
        id<MTLBuffer> buf_nframes = [g_device newBufferWithBytes:&n_frames_val
                                                         length:sizeof(uint32_t)
                                                        options:MTLResourceStorageModeShared];

        /* Command buffer */
        id<MTLCommandBuffer> cmdBuf = [g_queue commandBuffer];

        /* Pass 1: Haar Forward — one thread per byte */
        {
            id<MTLComputeCommandEncoder> enc = [cmdBuf computeCommandEncoder];
            [enc setComputePipelineState:g_haar_forward_pso];
            [enc setBuffer:buf_input offset:0 atIndex:0];
            [enc setBuffer:buf_frames offset:0 atIndex:1];

            NSUInteger threadWidth = g_haar_forward_pso.threadExecutionWidth;
            MTLSize gridSize = MTLSizeMake(n_bytes, 1, 1);
            MTLSize groupSize = MTLSizeMake(threadWidth, 1, 1);
            [enc dispatchThreads:gridSize threadsPerThreadgroup:groupSize];
            [enc endEncoding];
        }

        /* Pass 2: Transition Compute — one thread per transition */
        {
            id<MTLComputeCommandEncoder> enc = [cmdBuf computeCommandEncoder];
            [enc setComputePipelineState:g_transition_pso];
            [enc setBuffer:buf_frames offset:0 atIndex:0];
            [enc setBuffer:buf_tokens offset:0 atIndex:1];
            [enc setBuffer:buf_nframes offset:0 atIndex:2];

            NSUInteger threadWidth = g_transition_pso.threadExecutionWidth;
            MTLSize gridSize = MTLSizeMake(n_bytes - 1, 1, 1);
            MTLSize groupSize = MTLSizeMake(threadWidth, 1, 1);
            [enc dispatchThreads:gridSize threadsPerThreadgroup:groupSize];
            [enc endEncoding];
        }

        /* Execute and wait */
        [cmdBuf commit];
        [cmdBuf waitUntilCompleted];

        /* Read back tokens */
        uint8_t *gpu_tokens = (uint8_t *)[buf_tokens contents];

        /* CPU-side: RLE + Huffman + package (sequential, fast on small output) */
        h3x_init_lut();

        size_t n_tokens_total = (n_bytes - 1) * 8;

        /* RLE */
        size_t rle_max = n_tokens_total * 2;
        uint8_t *rle_buf = (uint8_t *)malloc(rle_max);
        size_t rle_len = h3x_rle_encode(gpu_tokens, n_tokens_total, rle_buf, rle_max);

        /* Huffman */
        uint32_t freqs[256] = {0};
        for (size_t i = 0; i < rle_len; i++) freqs[rle_buf[i]]++;

        H3X_HuffEntry huff_table[256];
        memset(huff_table, 0, sizeof(huff_table));
        h3x_huffman_build(freqs, 256, huff_table);

        size_t huff_max = rle_len * 2;
        uint8_t *huff_buf = (uint8_t *)malloc(huff_max);
        size_t huff_len = h3x_huffman_encode(rle_buf, rle_len, huff_table,
                                              huff_buf, huff_max);

        /* Assemble output */
        size_t total_out = sizeof(H3X_Header) + 1 + 6 + n_tokens_total * 4 + huff_len;
        *out_compressed = (uint8_t *)malloc(total_out);
        size_t pos = 0;

        H3X_Header header = {
            .magic = H3X_MAGIC,
            .version = H3X_VERSION,
            .flags = H3X_FLAG_HAS_RLE | H3X_FLAG_HAS_HUFFMAN,
            .anchor_stride = H3X_ANCHOR_STRIDE,
            .n_frames = (uint32_t)n_bytes,
            .n_transitions = (uint32_t)(n_bytes - 1),
            .base_frame_len = 1,
            .token_stream_len = (uint32_t)huff_len,
            .original_size = (uint32_t)n_bytes,
            .compression_ratio = (float)n_bytes / (float)(sizeof(H3X_Header) + 1 + huff_len)
        };

        memcpy(*out_compressed + pos, &header, sizeof(H3X_Header)); pos += sizeof(H3X_Header);
        (*out_compressed)[pos++] = data[0]; /* base frame */

        /* Huffman table */
        uint16_t n_active = 0;
        for (int i = 0; i < 256; i++) if (huff_table[i].length > 0) n_active++;
        memcpy(*out_compressed + pos, &n_active, 2); pos += 2;
        memcpy(*out_compressed + pos, &rle_len, 4); pos += 4;
        for (int i = 0; i < 256; i++) {
            if (huff_table[i].length > 0) {
                (*out_compressed)[pos++] = (uint8_t)i;
                (*out_compressed)[pos++] = huff_table[i].length;
                memcpy(*out_compressed + pos, &huff_table[i].code, 2); pos += 2;
            }
        }

        memcpy(*out_compressed + pos, huff_buf, huff_len); pos += huff_len;
        *out_len = pos;

        free(rle_buf);
        free(huff_buf);
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Metal Decode
 * For decode, GPU is used for the inverse Haar step after CPU reconstructs
 * the frame sequence from tokens. The sequential token-application is done
 * in segments on GPU via h3x_apply_transitions_segment.
 * ═══════════════════════════════════════════════════════════════════════════ */

int h3x_metal_decode(const uint8_t *compressed, size_t comp_len,
                     uint8_t **out_data, size_t *out_len) {
    /* Delegate to CPU decode — Metal decode is optional optimization
     * for very large tensors where segment-parallel reconstruction helps. */
    if (!compressed || comp_len < sizeof(H3X_Header)) return -1;

    H3X_Header header;
    memcpy(&header, compressed, sizeof(H3X_Header));
    if (header.magic != H3X_MAGIC) return -1;

    *out_data = (uint8_t *)malloc(header.original_size);
    *out_len = 0;

    int ret = h3x_decode(compressed, comp_len, *out_data, out_len);
    if (ret != 0) {
        free(*out_data);
        *out_data = NULL;
    }
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Cleanup
 * ═══════════════════════════════════════════════════════════════════════════ */

static void h3x_metal_cleanup(void) {
    g_haar_forward_pso = nil;
    g_transition_pso = nil;
    g_haar_inverse_pso = nil;
    g_apply_trans_pso = nil;
    g_library = nil;
    g_queue = nil;
    g_device = nil;
    g_metal_initialized = 0;
}

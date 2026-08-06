// ═══════════════════════════════════════════════════════════════════════════
// sha256.wgsl — GPU-accelerated SHA-256 for the h3x recovery deploy pipeline
// Author: Derek Hinch | QomputeAI
//
// Computes SHA-256 of a file loaded into a storage buffer. Each workgroup
// processes one file (identified by binding). The file is chunked into 64-byte
// blocks and processed sequentially within the workgroup's thread 0 (SHA-256
// is inherently sequential per-message, but we parallelize ACROSS files by
// dispatching one workgroup per file).
//
// For the Merkle tree pass (sha256_merkle.wgsl), we parallelize the pairwise
// hashing of leaves since those are independent.
//
// Bindings:
//   @group(0) @binding(0) — input file data (read-only storage)
//   @group(0) @binding(1) — output: 8x u32 = 32 bytes SHA-256 digest
//   @group(0) @binding(2) — metadata: [file_length_bytes]
// ═══════════════════════════════════════════════════════════════════════════

// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
const K: array<u32, 64> = array<u32, 64>(
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
);

// Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
const H_INIT: array<u32, 8> = array<u32, 8>(
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
);

@group(0) @binding(0) var<storage, read> file_data: array<u32>;
@group(0) @binding(1) var<storage, read_write> digest: array<u32, 8>;
@group(0) @binding(2) var<storage, read> metadata: array<u32, 1>;  // [0] = byte length

fn rotr(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (~x & z);
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn sigma0(x: u32) -> u32 {
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

fn sigma1(x: u32) -> u32 {
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

fn gamma0(x: u32) -> u32 {
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

fn gamma1(x: u32) -> u32 {
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

// Read a big-endian u32 from the file_data array at byte offset `byte_off`.
// file_data is packed as little-endian u32s, so we reconstruct big-endian.
fn read_be_u32(byte_off: u32) -> u32 {
    let word_idx = byte_off / 4u;
    let le_word = file_data[word_idx];
    // Swap endianness: LE storage -> BE for SHA-256
    return ((le_word & 0xffu) << 24u) |
           (((le_word >> 8u) & 0xffu) << 16u) |
           (((le_word >> 16u) & 0xffu) << 8u) |
           ((le_word >> 24u) & 0xffu);
}

// Process a single 64-byte (512-bit) block starting at `block_byte_off`.
// `h` is modified in place.
fn process_block(block_byte_off: u32, h: ptr<function, array<u32, 8>>) {
    // Prepare message schedule W[0..63]
    var w: array<u32, 64>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        w[i] = read_be_u32(block_byte_off + i * 4u);
    }
    for (var i = 16u; i < 64u; i = i + 1u) {
        w[i] = gamma1(w[i - 2u]) + w[i - 7u] + gamma0(w[i - 15u]) + w[i - 16u];
    }

    // Working variables
    var a = (*h)[0]; var b = (*h)[1]; var c = (*h)[2]; var d = (*h)[3];
    var e = (*h)[4]; var f = (*h)[5]; var g = (*h)[6]; var hh = (*h)[7];

    // 64 rounds
    for (var i = 0u; i < 64u; i = i + 1u) {
        let t1 = hh + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        let t2 = sigma0(a) + maj(a, b, c);
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    (*h)[0] = (*h)[0] + a; (*h)[1] = (*h)[1] + b;
    (*h)[2] = (*h)[2] + c; (*h)[3] = (*h)[3] + d;
    (*h)[4] = (*h)[4] + e; (*h)[5] = (*h)[5] + f;
    (*h)[6] = (*h)[6] + g; (*h)[7] = (*h)[7] + hh;
}

@compute @workgroup_size(1)
fn sha256_main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let file_len = metadata[0];

    // Initialize hash state
    var h: array<u32, 8>;
    for (var i = 0u; i < 8u; i = i + 1u) {
        h[i] = H_INIT[i];
    }

    // Number of complete 64-byte blocks
    let n_full_blocks = file_len / 64u;

    // Process complete blocks
    for (var b = 0u; b < n_full_blocks; b = b + 1u) {
        process_block(b * 64u, &h);
    }

    // ── Padding ──
    // SHA-256 padding: append 0x80, then zeros, then 64-bit big-endian bit length.
    // The padded message must be a multiple of 64 bytes.
    // We handle the last partial block + padding in a temporary buffer.
    let remaining = file_len - n_full_blocks * 64u;
    let bit_len: u64 = u64(file_len) * 8u64;

    // We need 1 or 2 padding blocks depending on remaining bytes.
    // If remaining <= 55, one block suffices. Otherwise two.
    var pad_block_count: u32;
    if (remaining <= 55u) {
        pad_block_count = 1u;
    } else {
        pad_block_count = 2u;
    }

    // Build padding blocks by writing to file_data conceptually.
    // Since file_data is read-only, we process the tail differently:
    // We'll reconstruct the padded words manually.
    // For simplicity in the GPU shader, we assume the host pre-pads the input
    // buffer to a multiple of 64 bytes with correct SHA-256 padding.
    // This avoids complex byte-level writes in WGSL.
    //
    // The host MUST pad the buffer before dispatch. The `metadata[0]` value
    // is the ORIGINAL file length (for the length field in padding), and the
    // buffer is physically padded to ceil((file_len + 9) / 64) * 64 bytes.
    //
    // So we just process ALL blocks in file_data:
    let total_padded_blocks = arrayLength(&file_data) / 16u;  // 16 u32s = 64 bytes
    for (var b = n_full_blocks; b < total_padded_blocks; b = b + 1u) {
        process_block(b * 64u, &h);
    }

    // Write final digest
    for (var i = 0u; i < 8u; i = i + 1u) {
        digest[i] = h[i];
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// merkle.wgsl — Parallel Merkle tree construction via SHA-256
// Author: Derek Hinch | QomputeAI
//
// Constructs a binary Merkle tree from leaf hashes. Each dispatch pass
// reduces N hashes to N/2 by SHA-256(left || right). The host dispatches
// log2(N) passes, halving the workgroup count each time.
//
// Bindings:
//   @group(0) @binding(0) — input hashes: array of u32 (8 per hash = 32 bytes)
//   @group(0) @binding(1) — output hashes: array of u32 (8 per parent hash)
//   @group(0) @binding(2) — metadata: [num_pairs]
//
// Each workgroup processes ONE pair (left, right) → parent.
// Dispatch: num_pairs workgroups.
// ═══════════════════════════════════════════════════════════════════════════

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

const H_INIT: array<u32, 8> = array<u32, 8>(
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
);

@group(0) @binding(0) var<storage, read> input_hashes: array<u32>;
@group(0) @binding(1) var<storage, read_write> output_hashes: array<u32>;
@group(0) @binding(2) var<storage, read> meta: array<u32, 1>;  // [0] = num_pairs

fn rotr(x: u32, n: u32) -> u32 { return (x >> n) | (x << (32u - n)); }
fn ch(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ (~x & z); }
fn maj(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ (x & z) ^ (y & z); }
fn sigma0(x: u32) -> u32 { return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u); }
fn sigma1(x: u32) -> u32 { return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u); }
fn gamma0(x: u32) -> u32 { return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u); }
fn gamma1(x: u32) -> u32 { return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u); }

// SHA-256 of exactly 64 bytes (one block). Used for Merkle: hash(left32 || right32) = 64 bytes.
fn sha256_64bytes(data: array<u32, 16>) -> array<u32, 8> {
    var w: array<u32, 64>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        w[i] = data[i];
    }
    for (var i = 16u; i < 64u; i = i + 1u) {
        w[i] = gamma1(w[i - 2u]) + w[i - 7u] + gamma0(w[i - 15u]) + w[i - 16u];
    }

    var a = H_INIT[0]; var b = H_INIT[1]; var c = H_INIT[2]; var d = H_INIT[3];
    var e = H_INIT[4]; var f = H_INIT[5]; var g = H_INIT[6]; var hh = H_INIT[7];

    for (var i = 0u; i < 64u; i = i + 1u) {
        let t1 = hh + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        let t2 = sigma0(a) + maj(a, b, c);
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    var result: array<u32, 8>;
    result[0] = H_INIT[0] + a; result[1] = H_INIT[1] + b;
    result[2] = H_INIT[2] + c; result[3] = H_INIT[3] + d;
    result[4] = H_INIT[4] + e; result[5] = H_INIT[5] + f;
    result[6] = H_INIT[6] + g; result[7] = H_INIT[7] + hh;
    return result;
}

@compute @workgroup_size(1)
fn merkle_main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let pair_idx = gid.x;
    let num_pairs = meta[0];
    if (pair_idx >= num_pairs) { return; }

    // Read left hash (8 u32s) and right hash (8 u32s)
    let left_base = pair_idx * 2u * 8u;
    let right_base = (pair_idx * 2u + 1u) * 8u;

    // Concatenate into a 16-word (64-byte) block: left || right
    var block: array<u32, 16>;
    for (var i = 0u; i < 8u; i = i + 1u) {
        block[i] = input_hashes[left_base + i];
        block[8u + i] = input_hashes[right_base + i];
    }

    // Hash the concatenation
    let parent = sha256_64bytes(block);

    // Write parent hash to output
    let out_base = pair_idx * 8u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        output_hashes[out_base + i] = parent[i];
    }
}

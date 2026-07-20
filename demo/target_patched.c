/*
 * Target Program: PATCHED Version
 * Same algorithm, but with:
 * - Different variable names
 * - Reordered local computations
 * - Extra debug printf (dead code in production)
 * - Different formatting/whitespace
 *
 * The GEOMETRIC SIGNATURE should MATCH the original (same algorithm).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Rotate helper - same logic, different name */
static uint32_t rotl32(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

/* Key derivation - same algorithm, different variable names + order */
static void make_key(const char *phrase, uint8_t output_key[16]) {
    uint32_t state = 0x6a09e667;
    int idx = 0;
    while (phrase[idx] != '\0') {
        state ^= (uint32_t)phrase[idx];
        state = rotl32(state, 5);
        state += 0x9e3779b9;
        state ^= rotl32(state, 13);
        idx++;
    }
    /* Expand state into key bytes */
    int byte_idx;
    for (byte_idx = 0; byte_idx < 4; byte_idx++) {
        output_key[byte_idx*4+0] = (state >> 24) & 0xFF;
        output_key[byte_idx*4+1] = (state >> 16) & 0xFF;
        output_key[byte_idx*4+2] = (state >> 8)  & 0xFF;
        output_key[byte_idx*4+3] = (state >> 0)  & 0xFF;
        state = rotl32(state, 7) ^ 0xdeadbeef;
    }
}

/* MAC computation - identical logic */
static uint32_t authenticate(const uint8_t *msg, int msg_len, const uint8_t k[16]) {
    uint32_t tag = 0xfeedface;
    for (int pos = 0; pos < msg_len; pos++) {
        tag ^= (uint32_t)msg[pos] << ((pos % 4) * 8);
        tag = rotl32(tag, 3);
        tag += (uint32_t)k[pos % 16];
    }
    return tag;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <passphrase> <message>\n", argv[0]);
        return 1;
    }

    uint8_t k[16];
    make_key(argv[1], k);

    /* Same computation, produces same result */
    int mlen = (int)strlen(argv[2]);
    uint32_t tag = authenticate((uint8_t*)argv[2], mlen, k);

    printf("Key:  ");
    for (int i = 0; i < 16; i++) printf("%02x", k[i]);
    printf("\nMAC:  %08x\n", tag);
    printf("Auth: %s\n", tag != 0 ? "VALID" : "INVALID");

    return 0;
}

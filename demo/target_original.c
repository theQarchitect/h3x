/*
 * Target Program: Original Version
 * A simple key-derivation + message-authentication program.
 * We'll compile this multiple ways and show the geometric signature persists.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Simple HMAC-like construction (demonstration only, not crypto-secure) */
static uint32_t rotate_left(uint32_t val, int n) {
    return (val << n) | (val >> (32 - n));
}

static void derive_key(const char *passphrase, uint8_t key[16]) {
    uint32_t h = 0x6a09e667;
    for (int i = 0; passphrase[i]; i++) {
        h ^= (uint32_t)passphrase[i];
        h = rotate_left(h, 5);
        h += 0x9e3779b9;
        h ^= rotate_left(h, 13);
    }
    for (int i = 0; i < 4; i++) {
        key[i*4]   = (h >> 24) & 0xFF;
        key[i*4+1] = (h >> 16) & 0xFF;
        key[i*4+2] = (h >> 8) & 0xFF;
        key[i*4+3] = h & 0xFF;
        h = rotate_left(h, 7) ^ 0xdeadbeef;
    }
}

static uint32_t compute_mac(const uint8_t *data, int len, const uint8_t key[16]) {
    uint32_t mac = 0xfeedface;
    for (int i = 0; i < len; i++) {
        mac ^= (uint32_t)data[i] << ((i % 4) * 8);
        mac = rotate_left(mac, 3);
        mac += (uint32_t)key[i % 16];
    }
    return mac;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <passphrase> <message>\n", argv[0]);
        return 1;
    }

    uint8_t key[16];
    derive_key(argv[1], key);

    uint32_t mac = compute_mac((uint8_t*)argv[2], strlen(argv[2]), key);
    printf("Key:  ");
    for (int i = 0; i < 16; i++) printf("%02x", key[i]);
    printf("\nMAC:  %08x\n", mac);
    printf("Auth: %s\n", mac != 0 ? "VALID" : "INVALID");

    return 0;
}

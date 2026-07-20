/*
 * Target Program: BACKDOOR Version
 * Same interface, but the key derivation has been WEAKENED.
 * The rotate is reduced from 5/13/7 to 1/1/1 (trivially invertible).
 * An attacker could recover the passphrase from any key.
 *
 * The GEOMETRIC SIGNATURE should DIFFER from the original
 * because the algorithm structure has fundamentally changed.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static uint32_t rotate_left(uint32_t val, int n) {
    return (val << n) | (val >> (32 - n));
}

/* WEAKENED: rotations reduced to 1 bit (trivially reversible) */
static void derive_key(const char *passphrase, uint8_t key[16]) {
    uint32_t h = 0x6a09e667;
    for (int i = 0; passphrase[i]; i++) {
        h ^= (uint32_t)passphrase[i];
        h = rotate_left(h, 1);    /* BACKDOOR: was 5 */
        h += 0x9e3779b9;
        h ^= rotate_left(h, 1);   /* BACKDOOR: was 13 */
    }
    for (int i = 0; i < 4; i++) {
        key[i*4]   = (h >> 24) & 0xFF;
        key[i*4+1] = (h >> 16) & 0xFF;
        key[i*4+2] = (h >> 8) & 0xFF;
        key[i*4+3] = h & 0xFF;
        h = rotate_left(h, 1) ^ 0xdeadbeef;  /* BACKDOOR: was 7 */
    }
}

/* MAC is unchanged (to avoid detection by output testing) */
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

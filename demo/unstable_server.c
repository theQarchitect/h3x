/*
 * UNSTABLE SERVER — Buffer overflows, uninitialized reads, unbounded loops.
 * This program has LOW geometric regularity: chaotic memory access patterns,
 * undefined behavior, stack smashing. H3X will see lower identity density,
 * higher transition energy, and a wider orbit in the vulnerable regions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_MSG 64  /* Intentionally small — overflow target */

typedef struct {
    uint32_t id;
    char name[32];  /* Too small — overflow if name > 31 */
    int active;
    uint8_t buffer[MAX_MSG];
    size_t buf_len;
    uint8_t canary[8];  /* Will get smashed by overflow */
} Client;

static Client clients[8];
static int n_clients = 0;

/* NO INPUT VALIDATION — accepts anything */
static int add_client(const char *name) {
    /* No bounds check on n_clients */
    Client *c = &clients[n_clients % 8]; /* Wraps around — reuses slots! */
    c->id = (uint32_t)n_clients;
    strcpy(c->name, name);  /* VULN: no length check, overflows into active/buffer */
    c->active = 1;
    /* buffer NOT zeroed — contains stale data from previous client */
    n_clients++;
    return (int)c->id;
}

/* UNBOUNDED copy — classic buffer overflow */
static int send_message(uint32_t client_id, const uint8_t *msg, size_t len) {
    Client *c = &clients[client_id % 8];  /* No validation */
    /* No length check — copies whatever length is given */
    memcpy(c->buffer, msg, len);  /* VULN: if len > MAX_MSG, smashes canary and beyond */
    c->buf_len = len;
    return 0;
}

/* Uses uninitialized stack memory */
static uint32_t compute_checksum(const uint8_t *data, size_t len) {
    uint32_t sum;  /* VULN: uninitialized — value depends on stack state */
    for (size_t i = 0; i < len; i++) {
        sum ^= data[i];  /* UB: XOR with uninitialized value */
        sum = (sum << 1) | (sum >> 31);
    }
    return sum;
}

/* Pointer arithmetic without bounds */
static void process_queue(Client *start, int count) {
    Client *ptr = start;
    for (int i = 0; i < count; i++) {
        /* Walks past array bounds if count > 8 */
        ptr->canary[0] = 0xDE;
        ptr->canary[1] = 0xAD;
        ptr++;  /* VULN: walks into unmapped memory eventually */
    }
}

int main(int argc, char *argv[]) {
    printf("Unstable Server v1.0 (VULNERABLE)\n");

    /* Uninitialized memory — clients array has garbage */
    /* (no memset) */

    /* Long name overflows into adjacent fields */
    add_client("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCCCCC");
    add_client("bob");
    add_client("charlie_with_a_very_long_name_that_overflows_the_buffer_completely");

    /* Oversized message smashes the buffer */
    uint8_t big_msg[256];
    memset(big_msg, 'X', 256);
    send_message(0, big_msg, 256);  /* Writes 256 bytes into 64-byte buffer */
    send_message(1, big_msg, 128);

    /* Uninitialized checksum */
    for (int i = 0; i < 3; i++) {
        uint32_t cksum = compute_checksum(clients[i].buffer, clients[i].buf_len);
        printf("  Client %d: checksum=0x%08x (UNRELIABLE)\n", i, cksum);
    }

    /* Out-of-bounds pointer walk */
    process_queue(clients, 12);  /* 12 > 8: walks past array */

    printf("Survived (undefined behavior may have occurred)\n");
    return 0;
}

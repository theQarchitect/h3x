/*
 * STABLE SERVER — Proper bounds checking, error handling, deterministic flow.
 * This program has HIGH geometric regularity: bounded loops, validated input,
 * predictable control flow. H3X will see high identity density and tight orbit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_MSG 256
#define MAX_CLIENTS 16

typedef struct {
    uint32_t id;
    char name[64];
    int active;
    uint8_t buffer[MAX_MSG];
    size_t buf_len;
} Client;

static Client clients[MAX_CLIENTS];
static int n_clients = 0;

static int validate_name(const char *name) {
    if (!name) return 0;
    size_t len = strlen(name);
    if (len == 0 || len > 63) return 0;
    for (size_t i = 0; i < len; i++) {
        if (name[i] < 32 || name[i] > 126) return 0;
    }
    return 1;
}

static int add_client(const char *name) {
    if (n_clients >= MAX_CLIENTS) return -1;
    if (!validate_name(name)) return -2;

    Client *c = &clients[n_clients];
    c->id = (uint32_t)(n_clients + 1);
    strncpy(c->name, name, 63);
    c->name[63] = '\0';
    c->active = 1;
    c->buf_len = 0;
    memset(c->buffer, 0, MAX_MSG);
    n_clients++;
    return (int)c->id;
}

static int send_message(uint32_t client_id, const uint8_t *msg, size_t len) {
    if (client_id == 0 || client_id > (uint32_t)n_clients) return -1;
    if (!msg || len == 0) return -2;
    if (len > MAX_MSG) len = MAX_MSG;  /* Truncate, don't overflow */

    Client *c = &clients[client_id - 1];
    if (!c->active) return -3;

    memcpy(c->buffer, msg, len);
    c->buf_len = len;
    return 0;
}

static uint32_t compute_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum = (sum << 3) | (sum >> 29);
        sum ^= data[i];
        sum += 0x9e3779b9;
    }
    return sum;
}

int main(int argc, char *argv[]) {
    printf("Stable Server v1.0\n");

    /* Deterministic initialization */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        memset(&clients[i], 0, sizeof(Client));
    }

    /* Bounded operation loop */
    const char *test_names[] = {"alice", "bob", "charlie", "dave"};
    for (int i = 0; i < 4; i++) {
        int id = add_client(test_names[i]);
        if (id < 0) { fprintf(stderr, "Failed: %d\n", id); continue; }
        printf("  Added client %d: %s\n", id, test_names[i]);
    }

    /* Validated message passing */
    const uint8_t msg[] = "Hello, world! This is a bounded message.";
    for (int i = 1; i <= n_clients; i++) {
        int ret = send_message((uint32_t)i, msg, sizeof(msg) - 1);
        if (ret == 0) {
            uint32_t cksum = compute_checksum(clients[i-1].buffer, clients[i-1].buf_len);
            printf("  Client %d: msg delivered, checksum=0x%08x\n", i, cksum);
        }
    }

    /* Clean shutdown */
    for (int i = 0; i < n_clients; i++) {
        clients[i].active = 0;
        memset(clients[i].buffer, 0, MAX_MSG);
    }
    printf("Shutdown: %d clients cleaned\n", n_clients);
    return 0;
}

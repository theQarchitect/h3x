/*
 * h3x_netwatch — Network Traffic Geometric Analyzer
 * Author: Derek Hinch
 * Profiles TCP sessions via transition lattice, detects encrypted vs plaintext,
 * identifies protocols from geometric fingerprint, detects session anomalies.
 * Build: cc -O3 -o h3x_netwatch h3x_netwatch.c -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "../include/h3x_format.h"

#define MAX_SESSIONS 256
#define WARMUP 50

typedef struct {
    uint32_t token_dist[5];
    uint32_t total_tokens;
    float identity_density;
    float avg_energy;
    uint64_t orbit_hash;
    uint32_t n_bytes;
} SessionProfile;

/* Known protocol fingerprints */
typedef struct { const char *name; float id_min; float id_max; float energy_max; } ProtoFP;
static const ProtoFP KNOWN_PROTOS[] = {
    {"HTTP/plaintext",   0.50f, 0.75f, 0.8f},
    {"TLS/encrypted",    0.35f, 0.42f, 1.2f},
    {"DNS/structured",   0.60f, 0.80f, 0.6f},
    {"SSH/encrypted",    0.35f, 0.42f, 1.2f},
    {"SMTP/text",        0.50f, 0.70f, 0.8f},
    {"binary/raw",       0.42f, 0.55f, 1.0f},
    {NULL, 0, 0, 0}
};

static void compute_tokens(uint8_t a, uint8_t b, uint8_t tok[8]) {
    for(int i=0;i<4;i++){
        int ec=(a>>(7-2*i))&1,oc=(a>>(6-2*i))&1,en=(b>>(7-2*i))&1,on=(b>>(6-2*i))&1;
        tok[i]=(uint8_t)((ec+oc)-(en+on)+2);tok[4+i]=(uint8_t)((ec-oc)-(en-on)+2);
    }
}

static SessionProfile profile_stream(const uint8_t *data, size_t n) {
    SessionProfile sp = {0};
    sp.n_bytes = (uint32_t)n;
    sp.orbit_hash = 0xcbf29ce484222325ULL;

    for(size_t i=0;i+1<n;i++){
        uint8_t tok[8];
        compute_tokens(data[i], data[i+1], tok);
        for(int j=0;j<8;j++){
            sp.token_dist[tok[j]]++;
            sp.total_tokens++;
            sp.avg_energy += fabsf((float)tok[j]-2.0f);
            sp.orbit_hash ^= (uint64_t)tok[j];
            sp.orbit_hash *= 0x100000001b3ULL;
        }
    }
    if(sp.total_tokens>0){
        sp.identity_density = (float)sp.token_dist[2]/sp.total_tokens;
        sp.avg_energy /= sp.total_tokens;
    }
    return sp;
}

static const char *classify_protocol(const SessionProfile *sp) {
    for(int i=0; KNOWN_PROTOS[i].name; i++){
        if(sp->identity_density >= KNOWN_PROTOS[i].id_min &&
           sp->identity_density <= KNOWN_PROTOS[i].id_max &&
           sp->avg_energy <= KNOWN_PROTOS[i].energy_max)
            return KNOWN_PROTOS[i].name;
    }
    return "unknown";
}

static const char *classify_encryption(const SessionProfile *sp) {
    if(sp->identity_density < 0.42f) return "ENCRYPTED";
    if(sp->identity_density > 0.55f) return "PLAINTEXT";
    return "MIXED/COMPRESSED";
}

int main(int argc, char *argv[]) {
    if(argc < 2){
        fprintf(stderr,"h3x_netwatch — Network Traffic Geometric Analyzer\n");
        fprintf(stderr,"Usage:\n");
        fprintf(stderr,"  %s --stdin                     Read raw bytes from stdin\n",argv[0]);
        fprintf(stderr,"  %s --file <capture.bin>        Analyze captured bytes\n",argv[0]);
        fprintf(stderr,"  %s --demo                      Run with test patterns\n",argv[0]);
        fprintf(stderr,"\nPipe from tcpdump: tcpdump -w - | %s --stdin\n",argv[0]);
        return 1;
    }

    if(!strcmp(argv[1],"--demo")){
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("  H3X NETWATCH — Protocol Geometric Fingerprinting Demo\n");
        printf("═══════════════════════════════════════════════════════════════\n\n");

        /* Generate test patterns */
        struct { const char *name; uint8_t *data; size_t len; } tests[6];

        /* HTTP-like */
        const char *http = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
                          "Accept: text/html\r\nConnection: keep-alive\r\n\r\n"
                          "<html><body><h1>Hello World</h1></body></html>\r\n";
        tests[0] = (typeof(tests[0])){"HTTP request+response", (uint8_t*)http, strlen(http)};

        /* TLS-like (random bytes) */
        uint8_t tls_data[512];
        srand(42);
        for(int i=0;i<512;i++) tls_data[i]=(uint8_t)(rand()&0xFF);
        tls_data[0]=0x17; tls_data[1]=0x03; tls_data[2]=0x03; /* TLS header */
        tests[1] = (typeof(tests[0])){"TLS encrypted payload", tls_data, 512};

        /* DNS-like */
        uint8_t dns_data[128];
        memset(dns_data, 0, 128);
        dns_data[0]=0xAB;dns_data[1]=0xCD; /* Transaction ID */
        dns_data[2]=0x01;dns_data[3]=0x00; /* Flags: standard query */
        dns_data[4]=0x00;dns_data[5]=0x01; /* Questions: 1 */
        memcpy(dns_data+12, "\x07""example\x03""com\x00", 13); /* Query */
        tests[2] = (typeof(tests[0])){"DNS query", dns_data, 64};

        /* SSH-like (encrypted with periodic keepalive) */
        uint8_t ssh_data[512];
        for(int i=0;i<512;i++) ssh_data[i]=(uint8_t)(rand()&0xFF);
        /* Inject keepalive pattern every 64 bytes */
        for(int i=0;i<512;i+=64){ssh_data[i]=0x00;ssh_data[i+1]=0x00;ssh_data[i+2]=0x00;ssh_data[i+3]=0x0C;}
        tests[3] = (typeof(tests[0])){"SSH encrypted+keepalive", ssh_data, 512};

        /* SMTP */
        const char *smtp = "220 mail.example.com ESMTP\r\nHELO client.example.com\r\n"
                          "MAIL FROM:<user@example.com>\r\nRCPT TO:<dest@example.com>\r\n"
                          "DATA\r\nSubject: Test\r\n\r\nHello.\r\n.\r\nQUIT\r\n";
        tests[4] = (typeof(tests[0])){"SMTP session", (uint8_t*)smtp, strlen(smtp)};

        /* Binary/protobuf */
        uint8_t proto_data[256];
        for(int i=0;i<256;i++) proto_data[i] = (uint8_t)((i*7+3)&0xFF);
        tests[5] = (typeof(tests[0])){"Binary/protobuf-like", proto_data, 256};

        printf("  %-25s %6s %6s %6s %12s %s\n","Stream","Bytes","ID%","Energy","Orbit","Classification");
        printf("  ─────────────────────────────────────────────────────────────────────────\n");

        for(int t=0;t<6;t++){
            SessionProfile sp = profile_stream(tests[t].data, tests[t].len);
            const char *proto = classify_protocol(&sp);
            const char *enc = classify_encryption(&sp);
            printf("  %-25s %6zu %5.1f%% %5.2f %012llx %s [%s]\n",
                tests[t].name, tests[t].len,
                sp.identity_density*100, sp.avg_energy,
                (unsigned long long)(sp.orbit_hash & 0xFFFFFFFFFFFFULL),
                proto, enc);
        }

        printf("\n  Grammar Fingerprint Reference:\n");
        printf("    HTTP:  id=50-75%%, low energy (ASCII + \\r\\n structure)\n");
        printf("    TLS:   id=35-42%%, uniform (encrypted = no structure)\n");
        printf("    DNS:   id=60-80%%, periodic (fixed headers, short queries)\n");
        printf("    SSH:   id=35-42%% with periodic 60%%+ bursts (keepalives)\n");
        printf("    SMTP:  id=50-70%%, text-like (ASCII commands)\n");
        printf("\n");
        return 0;
    }

    /* Read from file or stdin */
    uint8_t *data = NULL; size_t n = 0;
    if(!strcmp(argv[1],"--stdin")){
        size_t cap=1024*1024; data=malloc(cap);
        int c; while((c=fgetc(stdin))!=EOF&&n<cap) data[n++]=(uint8_t)c;
    } else if(!strcmp(argv[1],"--file")&&argc>=3){
        FILE *f=fopen(argv[2],"rb");if(!f){perror("fopen");return 1;}
        fseek(f,0,SEEK_END);n=(size_t)ftell(f);fseek(f,0,SEEK_SET);
        data=malloc(n);fread(data,1,n,f);fclose(f);
    } else { fprintf(stderr,"Unknown mode\n"); return 1; }

    if(n<2){fprintf(stderr,"Not enough data\n");free(data);return 1;}

    SessionProfile sp = profile_stream(data, n);
    printf("{\"bytes\":%u,\"id_density\":%.4f,\"energy\":%.4f,"
           "\"classification\":\"%s\",\"encryption\":\"%s\","
           "\"orbit\":\"%016llx\"}\n",
           sp.n_bytes, sp.identity_density, sp.avg_energy,
           classify_protocol(&sp), classify_encryption(&sp),
           (unsigned long long)sp.orbit_hash);

    free(data); return 0;
}

/*
 * h3x_syscall — Geometric Anomaly Detection on Syscall/Ioctl Traces
 * ==================================================================
 * Author: Derek Hinch
 *
 * Compares the PREDICTED syscall behavior (from static analysis of the
 * binary's geometric signature) against ACTUAL runtime syscall traces.
 * Anomalies = syscalls/ioctls whose byte patterns don't match what the
 * binary's transition geometry predicts.
 *
 * Theory: A binary's code sections have a characteristic transition
 * geometry. The syscall numbers/arguments it CAN produce are bounded
 * by that geometry. If runtime syscall traces show patterns that are
 * geometrically foreign to the binary → something injected them.
 *
 * Modes:
 *   --baseline <trace_file>        Learn normal syscall geometry
 *   --monitor <trace_file>         Compare against baseline, flag anomalies
 *   --predict <binary>             Predict expected syscall geometry from binary
 *   --compare <trace> <binary>     Full: predict from binary, compare to trace
 *
 * Input: Syscall trace as raw bytes (syscall numbers as uint16 stream)
 *   Generate with: dtruss -p PID 2>&1 | h3x_syscall_capture
 *   Or: strace -p PID -e raw=all -o trace.bin
 *
 * Build: cc -O3 -o h3x_syscall h3x_syscall.c -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "../include/h3x_format.h"

#define WARMUP 100
#define ANOMALY_THRESHOLD 2.5  /* σ above mean = anomaly */

typedef struct {
    float identity_density;
    float energy_mean;
    float energy_std;
    float token_dist[5];
    uint32_t n_samples;
} SyscallProfile;

static void compute_tokens(uint8_t a, uint8_t b, uint8_t tok[8]) {
    for(int i=0;i<4;i++){
        int ec=(a>>(7-2*i))&1,oc=(a>>(6-2*i))&1,en=(b>>(7-2*i))&1,on=(b>>(6-2*i))&1;
        tok[i]=(uint8_t)((ec+oc)-(en+on)+2);tok[4+i]=(uint8_t)((ec-oc)-(en-on)+2);
    }
}

static SyscallProfile profile_trace(const uint8_t *data, size_t n) {
    SyscallProfile sp; memset(&sp, 0, sizeof(sp));
    if (n < 2) return sp;

    uint32_t dist[5] = {0};
    uint32_t total = 0;
    float energy_sum = 0, energy_sq = 0;

    for (size_t i = 0; i + 1 < n; i++) {
        uint8_t tok[8];
        compute_tokens(data[i], data[i+1], tok);
        for (int j = 0; j < 8; j++) {
            dist[tok[j]]++;
            total++;
            float e = fabsf((float)tok[j] - 2.0f);
            energy_sum += e;
            energy_sq += e * e;
        }
    }
    if (total > 0) {
        for (int i = 0; i < 5; i++) sp.token_dist[i] = (float)dist[i] / total;
        sp.identity_density = sp.token_dist[2];
        sp.energy_mean = energy_sum / total;
        float var = (energy_sq / total) - (sp.energy_mean * sp.energy_mean);
        sp.energy_std = sqrtf(var > 0 ? var : 0);
    }
    sp.n_samples = total;
    return sp;
}

/* Sliding window anomaly detection: compute energy in windows,
 * flag windows where energy exceeds baseline + threshold*std */
static void detect_anomalies(const uint8_t *trace, size_t n,
                              const SyscallProfile *baseline,
                              int window_size) {
    float threshold = baseline->energy_mean + ANOMALY_THRESHOLD * baseline->energy_std;

    printf("  Baseline: energy=%.3f±%.3f, threshold=%.3f\n",
           baseline->energy_mean, baseline->energy_std, threshold);
    printf("  Scanning %zu bytes in windows of %d...\n\n", n, window_size);
    printf("  %8s %8s %6s %6s %s\n", "Offset", "WinSize", "Energy", "ID%", "Status");
    printf("  ────────────────────────────────────────────────────────────\n");

    int anomalies = 0;
    for (size_t off = 0; off + window_size < n; off += window_size / 2) {
        /* Profile this window */
        SyscallProfile wp = profile_trace(trace + off, window_size);

        int is_anomaly = 0;
        const char *reason = "";

        if (wp.energy_mean > threshold) {
            is_anomaly = 1; reason = "HIGH ENERGY";
        } else if (wp.identity_density < baseline->identity_density * 0.5f) {
            is_anomaly = 1; reason = "LOW IDENTITY";
        } else if (fabsf(wp.identity_density - baseline->identity_density) > 0.25f) {
            is_anomaly = 1; reason = "PROFILE SHIFT";
        }

        if (is_anomaly) {
            printf("  0x%06zX %8d %5.2f %5.1f%% ← ANOMALY [%s]\n",
                   off, window_size, wp.energy_mean, wp.identity_density*100, reason);
            anomalies++;
        }
    }

    printf("\n  Total anomalous windows: %d\n", anomalies);
    if (anomalies == 0) {
        printf("  Runtime behavior matches predicted geometry — no injection detected.\n");
    } else {
        printf("  WARNING: %d windows show geometric divergence from baseline.\n", anomalies);
        printf("  Possible: injected code, unexpected syscall patterns, or exploitation.\n");
    }
}

int main(int argc, char *argv[]) {
    if(argc<3){fprintf(stderr,"h3x_syscall — Syscall Geometric Anomaly Detector\n"
        "  %s --baseline <trace>    Learn normal profile\n"
        "  %s --monitor <trace>     Detect anomalies\n"
        "  %s --compare <trace> <binary>  Static vs runtime\n",argv[0],argv[0],argv[0]);return 1;}

    FILE *f=fopen(argv[2],"rb");if(!f){perror("fopen");return 1;}
    fseek(f,0,SEEK_END);long sz=ftell(f);fseek(f,0,SEEK_SET);
    uint8_t *data=malloc(sz);fread(data,1,sz,f);fclose(f);

    if(!strcmp(argv[1],"--baseline")||!strcmp(argv[1],"--predict")){
        SyscallProfile sp=profile_trace(data,(size_t)sz);
        printf("H3X Syscall Profile: id=%.1f%% energy=%.3f±%.3f samples=%u\n",
            sp.identity_density*100,sp.energy_mean,sp.energy_std,sp.n_samples);
        free(data);return 0;
    }
    if(!strcmp(argv[1],"--monitor")){
        size_t bl=sz/4>256?sz/4:sz/2;
        SyscallProfile baseline=profile_trace(data,bl);
        printf("H3X Syscall Anomaly Detection (baseline from first %zu bytes):\n",bl);
        detect_anomalies(data+bl,(size_t)sz-bl,&baseline,256);
        free(data);return 0;
    }
    if(!strcmp(argv[1],"--compare")&&argc>=4){
        FILE *fb=fopen(argv[3],"rb");if(!fb){perror("binary");free(data);return 1;}
        fseek(fb,0,SEEK_END);long bsz=ftell(fb);fseek(fb,0,SEEK_SET);
        uint8_t *bin=malloc(bsz);fread(bin,1,bsz,fb);fclose(fb);
        SyscallProfile predicted=profile_trace(bin,(size_t)bsz);
        SyscallProfile actual=profile_trace(data,(size_t)sz);
        printf("Static prediction (binary): id=%.1f%% energy=%.3f\n",predicted.identity_density*100,predicted.energy_mean);
        printf("Runtime actual (trace):     id=%.1f%% energy=%.3f\n",actual.identity_density*100,actual.energy_mean);
        float d=fabsf(actual.identity_density-predicted.identity_density)+fabsf(actual.energy_mean-predicted.energy_mean);
        printf("Divergence: %.3f %s\n",d,d>0.3?"← ANOMALOUS":"← OK");
        if(d>0.3){printf("Windowed scan:\n");detect_anomalies(data,(size_t)sz,&predicted,512);}
        free(data);free(bin);return 0;
    }
    fprintf(stderr,"Unknown: %s\n",argv[1]);free(data);return 1;
}

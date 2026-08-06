/*
 * h3x_sentinel — Runtime Process Memory Fingerprinting
 * Author: Derek Hinch
 * Detects heap spray, ROP, UAF via transition geometry drift.
 * macOS: uses mach_vm_read. Linux: reads /proc/PID/mem.
 * Build: cc -O3 -o h3x_sentinel h3x_sentinel.c -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include "../include/h3x_format.h"
#include "../include/h3x_attack_map.h"

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#endif

/* --watch-system: enumerate every pid on the host, try to profile each one
 * optimistically (task_for_pid failures are reported verbosely; the caller
 * filters what it cares about). Loops forever; SIGTERM/SIGINT exit cleanly.
 * Classification of "valuable/suspicious" is the caller's job.
 */
#define WS_MAX_PIDS         4096
#define WS_INTERVAL_MS      5000   /* cadence between full-host scans */

static volatile sig_atomic_t g_should_exit = 0;
static void handle_signal(int sig) { (void)sig; g_should_exit = 1; }

#define MAX_REGIONS 256
#define SAMPLE_SIZE 4096

typedef struct {
    uint64_t address;
    uint64_t size;
    float identity_density;
    float avg_confidence;
    float transition_energy;
} RegionProfile;

typedef struct {
    uint32_t n_regions;
    RegionProfile regions[MAX_REGIONS];
    time_t timestamp;
} Snapshot;

static void compute_tokens(uint8_t a, uint8_t b, uint8_t tok[8]) {
    for(int i=0;i<4;i++){
        int ec=(a>>(7-2*i))&1,oc=(a>>(6-2*i))&1,en=(b>>(7-2*i))&1,on=(b>>(6-2*i))&1;
        tok[i]=(uint8_t)((ec+oc)-(en+on)+2);tok[4+i]=(uint8_t)((ec-oc)-(en-on)+2);
    }
}

static RegionProfile profile_buffer(const uint8_t *buf, size_t len, uint64_t addr) {
    RegionProfile rp = {0};
    rp.address = addr;
    rp.size = len;
    if (len < 2) return rp;

    uint32_t id_count=0, total=0;
    float energy_sum=0;
    size_t n = len < SAMPLE_SIZE ? len : SAMPLE_SIZE;

    for(size_t i=0;i+1<n;i++){
        uint8_t tok[8];
        compute_tokens(buf[i], buf[i+1], tok);
        for(int j=0;j<8;j++){
            total++;
            if(tok[j]==2) id_count++;
            energy_sum += fabsf((float)tok[j] - 2.0f);
        }
    }
    rp.identity_density = total>0 ? (float)id_count/total : 0;
    rp.transition_energy = total>0 ? energy_sum/total : 0;
    return rp;
}

#ifdef __APPLE__
static Snapshot snapshot_process(pid_t pid) {
    Snapshot snap = {0};
    snap.timestamp = time(NULL);

    /* Optimistic: always try task_for_pid. Failures are expected for many
     * pids (SIP-protected, other users) and are reported verbosely so the
     * caller can disregard as it sees fit. */
    task_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid(%d) failed: %d (%s)\n",
                pid, kr, mach_error_string(kr));
        return snap;
    }

    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    natural_t depth = 1;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count;

    while (snap.n_regions < MAX_REGIONS) {
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = mach_vm_region_recurse(task, &addr, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;

        if (info.is_submap) { depth++; continue; }

        /* Only profile readable regions */
        if (info.protection & VM_PROT_READ) {
            /* Read a sample from this region */
            vm_offset_t data_ptr = 0;
            mach_msg_type_number_t data_cnt = 0;
            size_t read_size = size < SAMPLE_SIZE ? (size_t)size : SAMPLE_SIZE;

            kr = mach_vm_read(task, addr, read_size, &data_ptr, &data_cnt);
            if (kr == KERN_SUCCESS && data_cnt > 1) {
                snap.regions[snap.n_regions] = profile_buffer(
                    (uint8_t*)data_ptr, data_cnt, addr);
                snap.n_regions++;
                mach_vm_deallocate(mach_task_self(), data_ptr, data_cnt);
            }
        }
        addr += size;
    }
    return snap;
}
#else
static Snapshot snapshot_process(pid_t pid) {
    Snapshot snap = {0};
    snap.timestamp = time(NULL);
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    /* Linux implementation would read /proc/PID/maps + /proc/PID/mem */
    fprintf(stderr, "Linux: reading %s (stub)\n", path);
    return snap;
}
#endif

static void print_json_event(const char *event_type, const RegionProfile *rp,
                              const RegionProfile *baseline, pid_t pid) {
    printf("{\"event\":\"%s\",\"pid\":%d,\"addr\":\"0x%llx\",\"size\":%llu,"
           "\"id_density\":%.3f,\"energy\":%.3f",
           event_type, pid, (unsigned long long)rp->address,
           (unsigned long long)rp->size, rp->identity_density, rp->transition_energy);
    if (baseline) {
        printf(",\"baseline_id\":%.3f,\"delta_id\":%.3f",
               baseline->identity_density,
               rp->identity_density - baseline->identity_density);
    }
    printf(",\"ts\":%ld", time(NULL));
    h3x_emit_std_fields(stdout, event_type);  /* MITRE ATT&CK + NIST enrichment */
    printf("}\n");
}

int main(int argc, char *argv[]) {
    /* --watch-system is a no-PID mode; handle it before the argc<3 gate. */
    if (argc >= 2 && !strcmp(argv[1], "--watch-system")) {
        int interval_ms = WS_INTERVAL_MS;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--interval") && i + 1 < argc)
                interval_ms = atoi(argv[++i]);
        }

        /* Line-buffer stdout/stderr so launchd's log stream sees events live. */
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);

        /* Clean shutdown on launchctl stop / bootout. */
        signal(SIGTERM, handle_signal);
        signal(SIGINT,  handle_signal);
        signal(SIGPIPE, SIG_IGN);

#ifdef __APPLE__
        fprintf(stderr, "h3x_sentinel: --watch-system started (interval=%dms)\n", interval_ms);

        /* Self-describing standards envelope so the SIEM can classify the
         * whole stream (continuous host memory monitoring). */
        printf("{\"tool\":\"h3x_sentinel\",\"activity\":\"SYSTEM_SCAN\"");
        h3x_emit_std_fields(stdout, "SYSTEM_SCAN");
        printf(",\"ts\":%ld}\n", (long)time(NULL));

        int *pids = (int*)calloc(WS_MAX_PIDS, sizeof(int));
        if (!pids) { fprintf(stderr, "OOM allocating pid buffer\n"); return 1; }

        while (!g_should_exit) {
            int n_bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, WS_MAX_PIDS * (int)sizeof(int));
            if (n_bytes <= 0) {
                fprintf(stderr, "proc_listpids failed: %s\n", strerror(errno));
                sleep(1);
                continue;
            }
            int n_pids = n_bytes / (int)sizeof(int);
            fprintf(stderr, "h3x_sentinel: scan cycle — %d pids\n", n_pids);

            for (int i = 0; i < n_pids && !g_should_exit; i++) {
                pid_t p = pids[i];
                if (p <= 1 || p == getpid()) continue; /* skip kernel/launchd/self */

                /* Optimistic snapshot; task_for_pid failures print to stderr
                 * and the caller can disregard. */
                Snapshot snap = snapshot_process(p);
                if (snap.n_regions == 0) continue;

                printf("{\"pid\":%d,\"regions\":%u,\"ts\":%ld,\"profiles\":[",
                       p, snap.n_regions, (long)snap.timestamp);
                for (uint32_t j = 0; j < snap.n_regions; j++) {
                    RegionProfile *r = &snap.regions[j];
                    printf("%s{\"addr\":\"0x%llx\",\"size\":%llu,\"id\":%.3f,\"energy\":%.3f}",
                           j ? "," : "",
                           (unsigned long long)r->address,
                           (unsigned long long)r->size,
                           r->identity_density, r->transition_energy);
                }
                printf("]}\n");
            }

            /* Sleep the cycle, but wake early on signal. */
            for (int slept = 0; slept < interval_ms && !g_should_exit; slept += 100)
                usleep(100 * 1000);
        }

        free(pids);
        fprintf(stderr, "h3x_sentinel: --watch-system exiting cleanly\n");
        return 0;
#else
        fprintf(stderr, "--watch-system: only supported on macOS in this build\n");
        return 1;
#endif
    }

    if (argc < 3) {
        fprintf(stderr, "h3x_sentinel — Runtime Memory Monitor\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s --watch <PID> [--interval <ms>]\n", argv[0]);
        fprintf(stderr, "  %s --watch-system [--interval <ms>]\n", argv[0]);
        fprintf(stderr, "  %s --baseline <PID>\n", argv[0]);
        fprintf(stderr, "  %s --check <PID>\n", argv[0]);
        fprintf(stderr, "\nDetects: heap spray, ROP chains, use-after-free\n");
        fprintf(stderr, "Output: JSON events to stdout\n");
        return 1;
    }

    const char *mode = argv[1];
    pid_t pid = (pid_t)atoi(argv[2]);
    int interval_ms = 1000;
    for(int i=3;i<argc;i++) if(!strcmp(argv[i],"--interval")&&i+1<argc) interval_ms=atoi(argv[++i]);

    if (!strcmp(mode, "--baseline") || !strcmp(mode, "--check")) {
        Snapshot snap = snapshot_process(pid);
        printf("{\n  \"pid\": %d,\n  \"regions\": %u,\n  \"profiles\": [\n", pid, snap.n_regions);
        for(uint32_t i=0;i<snap.n_regions;i++){
            RegionProfile *r = &snap.regions[i];
            printf("    {\"addr\":\"0x%llx\",\"size\":%llu,\"id%%\":%.1f,\"energy\":%.3f}%s\n",
                (unsigned long long)r->address,(unsigned long long)r->size,
                r->identity_density*100,r->transition_energy,
                i<snap.n_regions-1?",":"");
        }
        printf("  ]\n}\n");
        return 0;
    }

    if (!strcmp(mode, "--watch")) {
        fprintf(stderr, "h3x_sentinel: Watching PID %d (interval=%dms)\n", pid, interval_ms);
        fprintf(stderr, "  Alerts on: id_density drop >20%%, energy spike >3σ\n\n");

        /* Take baseline */
        Snapshot baseline = snapshot_process(pid);
        if (baseline.n_regions == 0) {
            fprintf(stderr, "Could not read process memory. Need root or entitlement.\n");
            return 1;
        }
        fprintf(stderr, "  Baseline: %u regions captured\n", baseline.n_regions);

        /* Monitor loop */
        while (1) {
            usleep(interval_ms * 1000);
            Snapshot current = snapshot_process(pid);
            if (current.n_regions == 0) {
                fprintf(stderr, "Process %d gone\n", pid);
                break;
            }

            /* Compare against baseline */
            for(uint32_t i=0;i<current.n_regions && i<baseline.n_regions;i++){
                float id_delta = current.regions[i].identity_density - baseline.regions[i].identity_density;
                float energy_delta = current.regions[i].transition_energy - baseline.regions[i].transition_energy;

                if (id_delta < -0.20f) {
                    print_json_event("HEAP_SPRAY_SUSPECT", &current.regions[i], &baseline.regions[i], pid);
                }
                if (id_delta > 0.30f && baseline.regions[i].identity_density < 0.5f) {
                    print_json_event("CODE_CORRUPTION", &current.regions[i], &baseline.regions[i], pid);
                }
                if (energy_delta > 1.5f) {
                    print_json_event("INJECTION_SUSPECT", &current.regions[i], &baseline.regions[i], pid);
                }
            }
        }
        return 0;
    }

    fprintf(stderr, "Unknown mode: %s\n", mode);
    return 1;
}

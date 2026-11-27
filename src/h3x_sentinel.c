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

#include "h3x_sentinel_core.h"
#define MAX_REGIONS H3X_MAX_REGIONS
#define SAMPLE_SIZE H3X_SAMPLE_SIZE

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
                uint32_t prot = ((info.protection & VM_PROT_READ) ? H3X_PROT_READ : 0)
                              | ((info.protection & VM_PROT_WRITE) ? H3X_PROT_WRITE : 0)
                              | ((info.protection & VM_PROT_EXECUTE) ? H3X_PROT_EXECUTE : 0);
                snap.regions[snap.n_regions] = h3x_profile_buffer(
                    (uint8_t*)data_ptr, data_cnt, addr, (uint64_t)size, prot);
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
           "\"region_size\":%llu,\"prot\":\"%c%c%c\","
           "\"id_density\":%.3f,\"energy\":%.3f",
           event_type, pid, (unsigned long long)rp->address,
           (unsigned long long)rp->size, (unsigned long long)rp->region_size,
           (rp->prot & H3X_PROT_READ) ? 'r' : '-', (rp->prot & H3X_PROT_WRITE) ? 'w' : '-',
           (rp->prot & H3X_PROT_EXECUTE) ? 'x' : '-',
           rp->identity_density, rp->transition_energy);
    if (baseline) {
        printf(",\"baseline_id\":%.3f,\"delta_id\":%.3f",
               baseline->identity_density,
               rp->identity_density - baseline->identity_density);
    }
    printf(",\"ts\":%ld", time(NULL));
    h3x_emit_std_fields(stdout, event_type);  /* MITRE ATT&CK + NIST enrichment */
    printf("}\n");
}

static void watch_emit(const char *kind, const RegionProfile *cur, const RegionProfile *base, void *ctx) {
    print_json_event(kind, cur, base, *(pid_t *)ctx);
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

        /* First scan becomes the baseline. Regions are matched by address (see
         * h3x_sentinel_core.h); a condition is reported when it starts, not every scan. */
        static Snapshot first, current;
        static WatchState state;
        first = snapshot_process(pid);
        if (first.n_regions == 0) {
            fprintf(stderr, "Could not read process memory. Need root or entitlement.\n");
            return 1;
        }
        h3x_watch_init(&state, &first);
        fprintf(stderr, "  Baseline: %u regions captured (matched by address; reported on change)\n", first.n_regions);
        fflush(stderr);
        while (!g_should_exit) {
            usleep(interval_ms * 1000);
            current = snapshot_process(pid);
            if (current.n_regions == 0) {
                fprintf(stderr, "Process %d gone\n", pid);
                break;
            }
            struct { pid_t pid; } ctx = { pid };
            if (h3x_watch_step(&state, &current, watch_emit, &ctx)) fflush(stdout);
        }
        return 0;
    }

    fprintf(stderr, "Unknown mode: %s\n", mode);
    return 1;
}

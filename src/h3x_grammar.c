/*
 * h3x_grammar — Geometric Language/Format Detection & Injected Code Finder
 * =========================================================================
 * Author: Derek Hinch
 *
 * Identifies the underlying programming language or data format of any blob
 * by matching its transition geometry against a library of known grammar
 * fingerprints. Detects foreign code injection by comparing on-disk profile
 * against runtime memory profile.
 *
 * Key use case: A process compiled from C is running, but an attacker
 * injects Python/JS/shellcode into its heap. The grammar fingerprint of
 * the injected region will DIFFER from the host binary's fingerprint.
 * This tool detects that geometric mismatch.
 *
 * Modes:
 *   --identify <file>                 Identify language/format of a blob
 *   --compare-runtime <pid> <binary>  Compare on-disk vs runtime (find injections)
 *   --train <label> <file>            Add a new grammar fingerprint to library
 *   --library                         List known grammar fingerprints
 *
 * Build: cc -O3 -o h3x_grammar h3x_grammar.c -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../include/h3x_format.h"

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Grammar Fingerprint: a compact vector describing the geometric shape
 * of data conforming to a particular grammar/language.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char name[64];
    float identity_density;       /* % of identity tokens */
    float token_dist[5];          /* Normalized distribution of 5 states */
    float energy_mean;            /* Average |token - 2| */
    float energy_variance;        /* Variance of energy */
    float bigram_entropy;         /* Entropy of the bigram transition matrix */
    float autocorr_lag8;          /* Autocorrelation at lag 8 (byte boundary) */
    float autocorr_lag4;          /* Autocorrelation at lag 4 (nibble boundary) */
    uint64_t orbit_hash_sample;   /* Orbit hash of first 4K */
} GrammarFingerprint;

/* Built-in grammar library (empirically measured) */
static const GrammarFingerprint GRAMMAR_LIBRARY[] = {
    {"ARM64/Mach-O code",     0.52, {0.04,0.22,0.52,0.18,0.04}, 0.72, 0.30, 2.8, 0.46, 0.20, 0},
    {"ARM64/ELF code",        0.50, {0.05,0.21,0.50,0.20,0.04}, 0.74, 0.32, 2.9, 0.44, 0.18, 0},
    {"x86_64 code",           0.45, {0.06,0.23,0.45,0.20,0.06}, 0.80, 0.35, 3.0, 0.40, 0.15, 0},
    {"C source (ASCII)",      0.55, {0.03,0.20,0.55,0.19,0.03}, 0.62, 0.25, 2.5, 0.50, 0.30, 0},
    {"Python source",         0.58, {0.02,0.18,0.58,0.20,0.02}, 0.57, 0.20, 2.3, 0.55, 0.35, 0},
    {"JavaScript source",     0.54, {0.03,0.20,0.54,0.20,0.03}, 0.63, 0.26, 2.5, 0.48, 0.28, 0},
    {"JSON data",             0.60, {0.02,0.17,0.60,0.19,0.02}, 0.52, 0.18, 2.2, 0.52, 0.32, 0},
    {"XML/HTML",              0.55, {0.03,0.19,0.55,0.20,0.03}, 0.60, 0.22, 2.4, 0.50, 0.30, 0},
    {"Protobuf binary",       0.45, {0.05,0.22,0.45,0.23,0.05}, 0.77, 0.30, 2.8, 0.42, 0.20, 0},
    {"ASN.1/DER",             0.48, {0.04,0.22,0.48,0.22,0.04}, 0.73, 0.28, 2.7, 0.44, 0.22, 0},
    {"Shellcode (NOP sled)",  0.90, {0.01,0.04,0.90,0.04,0.01}, 0.10, 0.05, 0.5, 0.95, 0.90, 0},
    {"Shellcode (encoded)",   0.38, {0.06,0.25,0.38,0.25,0.06}, 0.86, 0.15, 3.1, 0.05, 0.03, 0},
    {"Encrypted/compressed",  0.38, {0.06,0.25,0.38,0.25,0.06}, 0.85, 0.10, 3.2, 0.02, 0.01, 0},
    {"Zero padding",          1.00, {0.00,0.00,1.00,0.00,0.00}, 0.00, 0.00, 0.0, 1.00, 1.00, 0},
    {"Float32 weights (NN)",  0.38, {0.06,0.25,0.38,0.25,0.06}, 0.84, 0.12, 3.1, 0.10, 0.05, 0},
    {"UTF-8 text",            0.52, {0.03,0.21,0.52,0.21,0.03}, 0.65, 0.25, 2.6, 0.48, 0.25, 0},
    {"PDF content",           0.50, {0.04,0.21,0.50,0.21,0.04}, 0.70, 0.28, 2.7, 0.40, 0.18, 0},
    {"SQLite DB",             0.65, {0.02,0.15,0.65,0.16,0.02}, 0.45, 0.15, 2.0, 0.60, 0.40, 0},
    {"",0,{0},0,0,0,0,0,0}  /* sentinel */
};

/* ═══════════════════════════════════════════════════════════════════════════ */

static void compute_tokens(uint8_t a, uint8_t b, uint8_t tok[8]) {
    for(int i=0;i<4;i++){
        int ec=(a>>(7-2*i))&1,oc=(a>>(6-2*i))&1,en=(b>>(7-2*i))&1,on=(b>>(6-2*i))&1;
        tok[i]=(uint8_t)((ec+oc)-(en+on)+2);tok[4+i]=(uint8_t)((ec-oc)-(en-on)+2);
    }
}

static GrammarFingerprint compute_fingerprint(const uint8_t *data, size_t n, const char *name) {
    GrammarFingerprint fp; memset(&fp, 0, sizeof(fp));
    if (name) strncpy(fp.name, name, 63);
    if (n < 2) return fp;

    uint32_t dist[5] = {0};
    uint64_t total = 0;
    float energy_sum = 0, energy_sq_sum = 0;
    uint64_t orbit = 0xcbf29ce484222325ULL;

    /* Bigram counts for entropy */
    uint32_t bigram[5][5]; memset(bigram, 0, sizeof(bigram));
    uint8_t prev_tok[8]; memset(prev_tok, 2, 8);

    /* Token stream for autocorrelation */
    size_t max_ac = n < 4096 ? n : 4096;
    float *tok_stream = calloc(max_ac * 8, sizeof(float));
    size_t ts_len = 0;

    for (size_t i = 0; i + 1 < n && i < max_ac; i++) {
        uint8_t tok[8];
        compute_tokens(data[i], data[i+1], tok);
        for (int j = 0; j < 8; j++) {
            dist[tok[j]]++;
            total++;
            float e = fabsf((float)tok[j] - 2.0f);
            energy_sum += e;
            energy_sq_sum += e * e;
            orbit ^= (uint64_t)tok[j]; orbit *= 0x100000001b3ULL;
            if (i > 0) bigram[prev_tok[j]][tok[j]]++;
            prev_tok[j] = tok[j];
            tok_stream[ts_len++] = (float)tok[j] - 2.0f;
        }
    }

    /* Compute fingerprint */
    if (total > 0) {
        for (int i = 0; i < 5; i++) fp.token_dist[i] = (float)dist[i] / total;
        fp.identity_density = fp.token_dist[2];
        fp.energy_mean = energy_sum / total;
        fp.energy_variance = (energy_sq_sum / total) - (fp.energy_mean * fp.energy_mean);
    }
    fp.orbit_hash_sample = orbit;

    /* Bigram entropy */
    float entropy = 0;
    uint32_t bg_total = 0;
    for (int i = 0; i < 5; i++) for (int j = 0; j < 5; j++) bg_total += bigram[i][j];
    if (bg_total > 0) {
        for (int i = 0; i < 5; i++) for (int j = 0; j < 5; j++) {
            if (bigram[i][j] > 0) {
                float p = (float)bigram[i][j] / bg_total;
                entropy -= p * log2f(p);
            }
        }
    }
    fp.bigram_entropy = entropy;

    /* Autocorrelation at lag 4 and 8 */
    if (ts_len > 16) {
        float mean = 0;
        for (size_t i = 0; i < ts_len; i++) mean += tok_stream[i];
        mean /= ts_len;

        float var = 0;
        for (size_t i = 0; i < ts_len; i++) var += (tok_stream[i]-mean)*(tok_stream[i]-mean);
        var /= ts_len;

        if (var > 0.001f) {
            float ac4 = 0, ac8 = 0;
            for (size_t i = 4; i < ts_len; i++) ac4 += (tok_stream[i]-mean)*(tok_stream[i-4]-mean);
            for (size_t i = 8; i < ts_len; i++) ac8 += (tok_stream[i]-mean)*(tok_stream[i-8]-mean);
            fp.autocorr_lag4 = ac4 / (ts_len * var);
            fp.autocorr_lag8 = ac8 / (ts_len * var);
        }
    }

    free(tok_stream);
    return fp;
}

static float fingerprint_distance(const GrammarFingerprint *a, const GrammarFingerprint *b) {
    /* Weighted Euclidean distance across all features */
    float d = 0;
    d += 4.0f * (a->identity_density - b->identity_density) * (a->identity_density - b->identity_density);
    for (int i = 0; i < 5; i++)
        d += 2.0f * (a->token_dist[i] - b->token_dist[i]) * (a->token_dist[i] - b->token_dist[i]);
    d += 1.0f * (a->energy_mean - b->energy_mean) * (a->energy_mean - b->energy_mean);
    d += 0.5f * (a->bigram_entropy - b->bigram_entropy) * (a->bigram_entropy - b->bigram_entropy);
    d += 1.0f * (a->autocorr_lag8 - b->autocorr_lag8) * (a->autocorr_lag8 - b->autocorr_lag8);
    return sqrtf(d);
}

static const char *identify_grammar(const GrammarFingerprint *fp, float *out_confidence) {
    float best_dist = 999.0f;
    const char *best_name = "unknown";
    float second_best = 999.0f;

    for (int i = 0; GRAMMAR_LIBRARY[i].name[0]; i++) {
        float d = fingerprint_distance(fp, &GRAMMAR_LIBRARY[i]);
        if (d < best_dist) {
            second_best = best_dist;
            best_dist = d;
            best_name = GRAMMAR_LIBRARY[i].name;
        } else if (d < second_best) {
            second_best = d;
        }
    }

    /* Confidence: ratio of gap between best and second-best */
    if (out_confidence) {
        *out_confidence = (second_best > 0.001f) ? 1.0f - (best_dist / second_best) : 0.0f;
        if (*out_confidence < 0) *out_confidence = 0;
    }
    return best_name;
}

/* ═══════════════════════════════════════════════════════════════════════════ */

#ifdef __APPLE__
static void compare_runtime(pid_t pid, const uint8_t *disk_data, size_t disk_size) {
    task_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed (%d). Need root or entitlement.\n", kr);
        return;
    }

    /* Compute disk grammar fingerprint */
    GrammarFingerprint disk_fp = compute_fingerprint(disk_data, disk_size, "on-disk");
    float disk_conf;
    const char *disk_grammar = identify_grammar(&disk_fp, &disk_conf);

    printf("  On-disk grammar: %s (confidence: %.0f%%)\n", disk_grammar, disk_conf*100);
    printf("  On-disk profile: id=%.1f%% energy=%.3f entropy=%.2f\n\n",
           disk_fp.identity_density*100, disk_fp.energy_mean, disk_fp.bigram_entropy);

    /* Scan runtime memory regions */
    printf("  Scanning PID %d memory regions...\n\n", pid);
    printf("  %12s %8s %20s %6s %s\n", "Address", "Size", "Grammar", "Conf", "Match?");
    printf("  ─────────────────────────────────────────────────────────────────\n");

    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    natural_t depth = 1;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count;
    int injections_found = 0;

    while (1) {
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = mach_vm_region_recurse(task, &addr, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;
        if (info.is_submap) { depth++; continue; }

        if ((info.protection & VM_PROT_READ) && size >= 256 && size < 10*1024*1024) {
            vm_offset_t data_ptr = 0;
            mach_msg_type_number_t data_cnt = 0;
            size_t read_size = size < 8192 ? (size_t)size : 8192;

            kr = mach_vm_read(task, addr, read_size, &data_ptr, &data_cnt);
            if (kr == KERN_SUCCESS && data_cnt > 64) {
                GrammarFingerprint region_fp = compute_fingerprint(
                    (uint8_t*)data_ptr, data_cnt, NULL);
                float region_conf;
                const char *region_grammar = identify_grammar(&region_fp, &region_conf);

                /* Check if this region's grammar matches the disk binary */
                float dist_to_disk = fingerprint_distance(&region_fp, &disk_fp);
                int is_foreign = (dist_to_disk > 0.3f && region_fp.identity_density < 0.9f);

                if (is_foreign) {
                    printf("  0x%010llx %6lluK %20s %5.0f%% ← FOREIGN CODE\n",
                        (unsigned long long)addr, (unsigned long long)(size/1024),
                        region_grammar, region_conf*100);
                    injections_found++;
                }

                mach_vm_deallocate(mach_task_self(), data_ptr, data_cnt);
            }
        }
        addr += size;
    }

    printf("\n  Foreign code regions detected: %d\n", injections_found);
    if (injections_found > 0) {
        printf("  WARNING: Process contains memory regions with grammar fingerprints\n");
        printf("  that do NOT match the on-disk binary. Possible code injection.\n");
    } else {
        printf("  All readable regions match expected grammar profile.\n");
    }
}
#endif

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "h3x_grammar — Geometric Language/Format Detection\n\n");
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s --identify <file>                Identify language/format\n", argv[0]);
        fprintf(stderr, "  %s --compare-runtime <pid> <binary> Find injected code\n", argv[0]);
        fprintf(stderr, "  %s --library                        List known fingerprints\n", argv[0]);
        fprintf(stderr, "  %s --profile <file>                 Print full fingerprint\n", argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "--library")) {
        printf("H3X Grammar Fingerprint Library:\n\n");
        printf("  %-25s %5s %5s %5s %5s\n", "Grammar", "ID%", "Energy", "Entropy", "AC8");
        printf("  ─────────────────────────────────────────────────────────────\n");
        for (int i = 0; GRAMMAR_LIBRARY[i].name[0]; i++) {
            const GrammarFingerprint *g = &GRAMMAR_LIBRARY[i];
            printf("  %-25s %4.0f%% %5.2f %7.2f %5.2f\n",
                g->name, g->identity_density*100, g->energy_mean,
                g->bigram_entropy, g->autocorr_lag8);
        }
        return 0;
    }

    if (!strcmp(argv[1], "--identify") && argc >= 3) {
        FILE *f = fopen(argv[2], "rb"); if (!f) { perror("fopen"); return 1; }
        fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
        uint8_t *data = malloc(sz); fread(data,1,sz,f); fclose(f);

        GrammarFingerprint fp = compute_fingerprint(data, (size_t)sz, argv[2]);
        float confidence;
        const char *grammar = identify_grammar(&fp, &confidence);

        printf("H3X Grammar Identification:\n");
        printf("  File: %s (%ld bytes)\n", argv[2], sz);
        printf("  Identified: %s\n", grammar);
        printf("  Confidence: %.0f%%\n\n", confidence * 100);
        printf("  Profile:\n");
        printf("    Identity density: %.1f%%\n", fp.identity_density * 100);
        printf("    Energy mean:      %.3f\n", fp.energy_mean);
        printf("    Bigram entropy:   %.2f bits\n", fp.bigram_entropy);
        printf("    Autocorr lag-8:   %.3f\n", fp.autocorr_lag8);
        printf("    Token dist: [%.1f%% %.1f%% %.1f%% %.1f%% %.1f%%]\n",
            fp.token_dist[0]*100, fp.token_dist[1]*100, fp.token_dist[2]*100,
            fp.token_dist[3]*100, fp.token_dist[4]*100);

        /* Show top-3 matches */
        printf("\n  Top matches:\n");
        float dists[64]; int indices[64]; int n_lib = 0;
        for (int i = 0; GRAMMAR_LIBRARY[i].name[0]; i++) {
            dists[i] = fingerprint_distance(&fp, &GRAMMAR_LIBRARY[i]);
            indices[i] = i;
            n_lib++;
        }
        /* Sort by distance */
        for (int i = 0; i < n_lib-1; i++)
            for (int j = i+1; j < n_lib; j++)
                if (dists[j] < dists[i]) {
                    float td=dists[i]; dists[i]=dists[j]; dists[j]=td;
                    int ti=indices[i]; indices[i]=indices[j]; indices[j]=ti;
                }
        for (int i = 0; i < 5 && i < n_lib; i++) {
            printf("    %d. %s (distance: %.3f)\n", i+1,
                GRAMMAR_LIBRARY[indices[i]].name, dists[i]);
        }

        free(data); return 0;
    }

    if (!strcmp(argv[1], "--profile") && argc >= 3) {
        FILE *f = fopen(argv[2], "rb"); if (!f) { perror("fopen"); return 1; }
        fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
        uint8_t *data = malloc(sz); fread(data,1,sz,f); fclose(f);

        GrammarFingerprint fp = compute_fingerprint(data, (size_t)sz, argv[2]);
        /* JSON output for use in training */
        printf("{\"name\":\"%s\",\"id\":%.4f,\"dist\":[%.4f,%.4f,%.4f,%.4f,%.4f],"
               "\"energy\":%.4f,\"variance\":%.4f,\"entropy\":%.4f,"
               "\"ac4\":%.4f,\"ac8\":%.4f,\"orbit\":\"%016llx\"}\n",
               argv[2], fp.identity_density,
               fp.token_dist[0],fp.token_dist[1],fp.token_dist[2],fp.token_dist[3],fp.token_dist[4],
               fp.energy_mean, fp.energy_variance, fp.bigram_entropy,
               fp.autocorr_lag4, fp.autocorr_lag8, (unsigned long long)fp.orbit_hash_sample);
        free(data); return 0;
    }

#ifdef __APPLE__
    if (!strcmp(argv[1], "--compare-runtime") && argc >= 4) {
        pid_t pid = (pid_t)atoi(argv[2]);
        FILE *f = fopen(argv[3], "rb"); if (!f) { perror("fopen"); return 1; }
        fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
        uint8_t *data = malloc(sz); fread(data,1,sz,f); fclose(f);

        printf("═══════════════════════════════════════════════════════════════\n");
        printf("  H3X GRAMMAR — Runtime vs Disk Comparison\n");
        printf("  PID: %d | Binary: %s\n", pid, argv[3]);
        printf("═══════════════════════════════════════════════════════════════\n\n");

        compare_runtime(pid, data, (size_t)sz);
        free(data); return 0;
    }
#endif

    if (!strcmp(argv[1], "--auto-learn")) {
        /* Scan all directories in PATH, fingerprint every executable,
         * cluster by geometric similarity, output a learned library */
        const char *path_env = getenv("PATH");
        if (!path_env) { fprintf(stderr, "PATH not set\n"); return 1; }

        printf("═══════════════════════════════════════════════════════════════\n");
        printf("  H3X GRAMMAR AUTO-LEARN — Scanning PATH\n");
        printf("═══════════════════════════════════════════════════════════════\n\n");

        #define MAX_LEARNED 512
        typedef struct { char path[256]; GrammarFingerprint fp; } LearnedEntry;
        LearnedEntry *learned = calloc(MAX_LEARNED, sizeof(LearnedEntry));
        int n_learned = 0;

        /* Parse PATH and scan each directory */
        char *path_copy = strdup(path_env);
        char *dir = strtok(path_copy, ":");
        int dirs_scanned = 0;

        while (dir && n_learned < MAX_LEARNED) {
            DIR *d = opendir(dir);
            if (!d) { dir = strtok(NULL, ":"); continue; }
            dirs_scanned++;

            struct dirent *ent;
            while ((ent = readdir(d)) && n_learned < MAX_LEARNED) {
                if (ent->d_name[0] == '.') continue;

                char fullpath[512];
                snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, ent->d_name);

                /* Check if it's a regular file and executable */
                struct stat st;
                if (stat(fullpath, &st) != 0) continue;
                if (!S_ISREG(st.st_mode)) continue;
                if (!(st.st_mode & S_IXUSR)) continue;
                if (st.st_size < 256 || st.st_size > 50*1024*1024) continue;

                /* Read first 8K for fingerprinting */
                FILE *fp = fopen(fullpath, "rb");
                if (!fp) continue;
                size_t read_size = st.st_size < 8192 ? st.st_size : 8192;
                uint8_t *buf = malloc(read_size);
                size_t got = fread(buf, 1, read_size, fp);
                fclose(fp);

                if (got < 64) { free(buf); continue; }

                GrammarFingerprint gfp = compute_fingerprint(buf, got, ent->d_name);
                strncpy(learned[n_learned].path, fullpath, 255);
                learned[n_learned].fp = gfp;
                n_learned++;
                free(buf);
            }
            closedir(d);
            dir = strtok(NULL, ":");
        }
        free(path_copy);

        printf("  Scanned %d directories, fingerprinted %d executables\n\n", dirs_scanned, n_learned);

        /* Cluster by geometric similarity using simple k-means-like grouping */
        #define MAX_CLUSTERS 20
        typedef struct {
            GrammarFingerprint centroid;
            int members[MAX_LEARNED];
            int n_members;
            char label[64];
        } Cluster;
        Cluster clusters[MAX_CLUSTERS];
        int n_clusters = 0;

        /* Greedy clustering: assign each entry to nearest cluster or create new */
        float CLUSTER_THRESHOLD = 0.25f;
        for (int i = 0; i < n_learned; i++) {
            int best_cluster = -1;
            float best_dist = CLUSTER_THRESHOLD;

            for (int c = 0; c < n_clusters; c++) {
                float d = fingerprint_distance(&learned[i].fp, &clusters[c].centroid);
                if (d < best_dist) { best_dist = d; best_cluster = c; }
            }

            if (best_cluster >= 0) {
                /* Add to existing cluster */
                if (clusters[best_cluster].n_members < MAX_LEARNED)
                    clusters[best_cluster].members[clusters[best_cluster].n_members++] = i;
            } else if (n_clusters < MAX_CLUSTERS) {
                /* Create new cluster */
                clusters[n_clusters].centroid = learned[i].fp;
                clusters[n_clusters].members[0] = i;
                clusters[n_clusters].n_members = 1;
                /* Auto-label from first member */
                const char *known = identify_grammar(&learned[i].fp, NULL);
                snprintf(clusters[n_clusters].label, 63, "%s", known);
                n_clusters++;
            }
        }

        /* Update centroids (average of members) */
        for (int c = 0; c < n_clusters; c++) {
            if (clusters[c].n_members == 0) continue;
            memset(&clusters[c].centroid, 0, sizeof(GrammarFingerprint));
            for (int m = 0; m < clusters[c].n_members; m++) {
                int idx = clusters[c].members[m];
                clusters[c].centroid.identity_density += learned[idx].fp.identity_density;
                clusters[c].centroid.energy_mean += learned[idx].fp.energy_mean;
                clusters[c].centroid.bigram_entropy += learned[idx].fp.bigram_entropy;
                clusters[c].centroid.autocorr_lag8 += learned[idx].fp.autocorr_lag8;
                for (int t = 0; t < 5; t++)
                    clusters[c].centroid.token_dist[t] += learned[idx].fp.token_dist[t];
            }
            int nm = clusters[c].n_members;
            clusters[c].centroid.identity_density /= nm;
            clusters[c].centroid.energy_mean /= nm;
            clusters[c].centroid.bigram_entropy /= nm;
            clusters[c].centroid.autocorr_lag8 /= nm;
            for (int t = 0; t < 5; t++) clusters[c].centroid.token_dist[t] /= nm;
        }

        /* Print clusters */
        printf("  ╔══════════════════════════════════════════════════════════════╗\n");
        printf("  ║  DISCOVERED GEOMETRIC CLUSTERS                              ║\n");
        printf("  ╚══════════════════════════════════════════════════════════════╝\n\n");
        printf("  %-4s %-25s %5s %5s %5s %5s  Examples\n",
               "#", "Classification", "ID%", "Enrgy", "Entr", "N");
        printf("  ─────────────────────────────────────────────────────────────────────\n");

        for (int c = 0; c < n_clusters; c++) {
            /* Show first 3 members as examples */
            char examples[256] = "";
            for (int m = 0; m < clusters[c].n_members && m < 3; m++) {
                int idx = clusters[c].members[m];
                const char *base = strrchr(learned[idx].path, '/');
                base = base ? base + 1 : learned[idx].path;
                if (m > 0) strcat(examples, ", ");
                strncat(examples, base, 20);
            }
            if (clusters[c].n_members > 3) {
                char more[32]; snprintf(more, 31, " +%d more", clusters[c].n_members - 3);
                strcat(examples, more);
            }

            printf("  %-4d %-25s %4.0f%% %5.2f %5.2f %5d  %s\n",
                   c + 1, clusters[c].label,
                   clusters[c].centroid.identity_density * 100,
                   clusters[c].centroid.energy_mean,
                   clusters[c].centroid.bigram_entropy,
                   clusters[c].n_members, examples);
        }

        /* Cross-cluster similarity matrix */
        if (n_clusters > 1) {
            printf("\n  ╔══════════════════════════════════════════════════════════════╗\n");
            printf("  ║  CROSS-CLUSTER SIMILARITY (shared geometric structure)     ║\n");
            printf("  ╚══════════════════════════════════════════════════════════════╝\n\n");
            printf("  %4s", "");
            for (int c = 0; c < n_clusters && c < 10; c++) printf(" %5d", c+1);
            printf("\n  ────");
            for (int c = 0; c < n_clusters && c < 10; c++) printf("──────");
            printf("\n");

            for (int i = 0; i < n_clusters && i < 10; i++) {
                printf("  %3d ", i+1);
                for (int j = 0; j < n_clusters && j < 10; j++) {
                    float d = fingerprint_distance(&clusters[i].centroid, &clusters[j].centroid);
                    float sim = 1.0f / (1.0f + d);
                    if (i == j) printf("  --- ");
                    else printf(" %4.0f%%", sim * 100);
                }
                printf("  %s\n", clusters[i].label);
            }
        }

        printf("\n  Total: %d executables → %d geometric clusters\n", n_learned, n_clusters);
        free(learned);
        return 0;
    }

    fprintf(stderr, "Unknown command or missing arguments.\n");
    return 1;
}

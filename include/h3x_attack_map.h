/*
 * h3x_attack_map.h — standards enrichment for h3x event streams
 * Author: Derek Hinch
 *
 * Maps each h3x finding/query to the canonical security frameworks so the
 * emitted JSON is SIEM- and compliance-ready out of the box:
 *
 *   • MITRE ATT&CK (Enterprise) — the adversary technique the signal relates
 *     to (a detection/collection relationship, not a claim of compromise).
 *   • NIST SP 800-53 Rev 5      — the security control the capability supports.
 *   • NIST CSF (v1.1)           — the Detect/Identify subcategory it feeds.
 *
 * These are compile-time constant tables of stable identifiers — no network,
 * no external dataset files, air-gap safe. A downstream correlator can join
 * these IDs against the full MITRE/NIST datasets it already holds.
 *
 * Single source of truth: both h3x_sentinel and h3x_lsof include this header
 * and call h3x_emit_std_fields() to append the mappings to an open JSON object.
 */
#ifndef H3X_ATTACK_MAP_H
#define H3X_ATTACK_MAP_H

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *key;          /* event type (sentinel) or query name (lsof) */
    const char *attack;       /* space-separated MITRE ATT&CK technique IDs   */
    const char *nist_800_53;  /* space-separated NIST SP 800-53 Rev 5 controls */
    const char *nist_csf;     /* space-separated NIST CSF v1.1 subcategories   */
} H3xStdMap;

static const H3xStdMap H3X_STD_MAP[] = {
    /* ── h3x_sentinel: runtime memory-geometry detections ────────────────── */
    /* heap spray drift → exploitation / injection primitive                  */
    { "HEAP_SPRAY_SUSPECT", "T1055 T1203",       "SI-4 SI-16",      "DE.CM-4 DE.AE-2" },
    /* executable region diverged from baseline → self-modifying / reflective */
    { "CODE_CORRUPTION",    "T1055 T1620 T1211", "SI-4 SI-7 SI-16", "DE.CM-4 DE.AE-2" },
    /* transition-energy spike → foreign code written into a mapping          */
    { "INJECTION_SUSPECT",  "T1055 T1620",       "SI-4 SI-16",      "DE.CM-4 DE.AE-2" },
    /* continuous host memory monitoring activity envelope                    */
    { "SYSTEM_SCAN",        "T1057",             "SI-4 CA-7",       "DE.CM-1 DE.CM-7" },

    /* ── h3x_lsof: privilege-separated introspection queries ─────────────── */
    { "fd",        "T1083",        "SI-4 AU-12",      "DE.CM-7" },
    { "net",       "T1049 T1046",  "SI-4 SC-7",       "DE.CM-1" },
    { "listen",    "T1049 T1046",  "SI-4 SC-7",       "DE.CM-1" },
    { "unix",      "T1559",        "SI-4",            "DE.CM-1" },
    { "handles",   "T1083 T1057",  "SI-4 AU-12",      "DE.CM-7" },
    { "resources", "T1083",        "SI-4 CM-8",       "DE.CM-7 ID.AM-2" },
    { "mmap",      "T1055 T1620",  "SI-4 SI-7",       "DE.CM-4" },
    { "deleted",   "T1070.004",    "SI-4 AU-9",       "DE.CM-1 DE.AE-2" },
    { "user",      "T1033",        "SI-4 AC-6",       "DE.CM-3" },
    /* model-weight files as sensitive assets: inventory + integrity + exfil  */
    { "weights",   "T1005 T1119",  "SI-4 SI-7 CM-8",  "ID.AM-2 DE.CM-7" },
};

static inline const H3xStdMap *h3x_std_lookup(const char *key) {
    if (!key) return 0;
    for (unsigned i = 0; i < sizeof(H3X_STD_MAP) / sizeof(H3X_STD_MAP[0]); i++)
        if (!strcmp(H3X_STD_MAP[i].key, key)) return &H3X_STD_MAP[i];
    return 0;
}

/* Print a space-separated id list as a JSON string array: "A B" -> ["A","B"] */
static inline void h3x_json_id_array(FILE *out, const char *ids) {
    fputc('[', out);
    int first = 1;
    const char *p = ids;
    while (p && *p) {
        while (*p == ' ') p++;
        const char *s = p;
        while (*p && *p != ' ') p++;
        if (p > s) {
            if (!first) fputc(',', out);
            first = 0;
            fputc('"', out);
            fwrite(s, 1, (size_t)(p - s), out);
            fputc('"', out);
        }
    }
    fputc(']', out);
}

/*
 * Append the standards fields to an already-open JSON object on `out`:
 *   ,"mitre_attack":[...],"nist_800_53":[...],"nist_csf":[...]
 * No-op if `key` is unknown, so callers can pass any event/query name safely.
 */
static inline void h3x_emit_std_fields(FILE *out, const char *key) {
    const H3xStdMap *m = h3x_std_lookup(key);
    if (!m) return;
    fputs(",\"mitre_attack\":", out); h3x_json_id_array(out, m->attack);
    fputs(",\"nist_800_53\":", out);  h3x_json_id_array(out, m->nist_800_53);
    fputs(",\"nist_csf\":", out);     h3x_json_id_array(out, m->nist_csf);
}

#endif /* H3X_ATTACK_MAP_H */

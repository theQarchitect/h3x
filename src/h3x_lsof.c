/*
 * h3x_lsof — Privilege-separated lsof broker
 * Author: Derek Hinch
 *
 * WHY THIS EXISTS
 * ===============
 * Deep host introspection (every process's file descriptors, sockets, mapped
 * images, and loaded model weights) requires root to see across user and
 * SIP boundaries. Handing a shell script setuid-root is unsafe and a script
 * cannot carry entitlements. This is the compiled, privilege-separated
 * alternative: a NON-root caller submits a request; lsof runs as ROOT here,
 * behind a fixed, validated interface.
 *
 * PRIVILEGE MODEL — "most investigative, lowest privilege"
 * ========================================================
 *   • Elevation is a single, auditable mechanism: this binary is installed
 *     setuid root (chown root:wheel, chmod 4755). That is the ONLY privilege.
 *   • The sole entitlement is com.apple.security.cs.debugger — the toolkit's
 *     narrowest cross-process investigative capability. Everything else
 *     (library-validation bypass, dyld env, get-task-allow, JIT) stays denied
 *     by the hardened runtime because it is never granted.
 *   • lsof is exec'd directly via execve() with an absolute path and a
 *     sanitized environment. No shell is ever invoked, so request strings
 *     cannot be interpreted as commands.
 *   • The common path exposes ZERO free-form input: the caller selects one of
 *     ten canned queries. The optional --custom path is flag-allow-listed and
 *     value-validated. Runtime is bounded by alarm().
 *
 * INTERFACE
 * =========
 *   h3x_lsof --list
 *   h3x_lsof <query> [pid|user]
 *   h3x_lsof --custom -- <validated lsof args...>
 *
 * Ten canned queries:
 *   fd <pid>        open file descriptors of a process
 *   net             all IP sockets (network), numeric
 *   listen          listening TCP sockets
 *   unix            UNIX-domain sockets (local IPC handles)
 *   handles <pid>   every open file/handle of a process
 *   resources <pid> open regular resource files of a process
 *   mmap <pid>      memory-mapped images / shared libraries of a process
 *   deleted         open-but-unlinked files across the host
 *   user <name>     files opened by a given user
 *   weights         model-weight files loaded in any running application
 *                   (.gguf/.safetensors/.pt/.onnx/.mlmodelc/... — NN weight ID)
 *
 * Output: one JSON object per open file to stdout; diagnostics to stderr.
 * Build:  cc -O3 -o h3x_lsof h3x_lsof.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>

#define LSOF_PATH   "/usr/sbin/lsof"
#define MAX_ARGS    32
#define LINE_MAX_   8192
#define RUN_TIMEOUT 25   /* seconds; bounds a heavy/hung lsof */

/* Post-exec filters applied while parsing lsof -F output. */
typedef enum { F_NONE = 0, F_REG, F_DELETED, F_WEIGHTS } Filter;
/* What extra argument a query consumes. */
typedef enum { A_NONE = 0, A_PID, A_USER } ArgKind;

typedef struct {
    const char *name;
    ArgKind     arg;
    Filter      filter;
    const char *desc;
} Query;

static const Query QUERIES[] = {
    { "fd",        A_PID,  F_NONE,    "open file descriptors of a process" },
    { "net",       A_NONE, F_NONE,    "all IP sockets (network), numeric" },
    { "listen",    A_NONE, F_NONE,    "listening TCP sockets" },
    { "unix",      A_NONE, F_NONE,    "UNIX-domain sockets (local IPC handles)" },
    { "handles",   A_PID,  F_NONE,    "every open file/handle of a process" },
    { "resources", A_PID,  F_REG,     "open regular resource files of a process" },
    { "mmap",      A_PID,  F_NONE,    "memory-mapped images / shared libraries" },
    { "deleted",   A_NONE, F_DELETED, "open-but-unlinked files across the host" },
    { "user",      A_USER, F_NONE,    "files opened by a given user" },
    { "weights",   A_NONE, F_WEIGHTS, "model-weight files in any running app (NN weight ID)" },
};
static const int N_QUERIES = (int)(sizeof(QUERIES) / sizeof(QUERIES[0]));

/* Known model-weight / checkpoint suffixes for the `weights` query. */
static const char *WEIGHT_EXT[] = {
    ".gguf", ".ggml", ".safetensors", ".bin", ".pt", ".pth", ".onnx",
    ".mlmodel", ".mlmodelc", ".mlpackage", ".npz", ".h5", ".pb", ".tflite",
    ".ckpt", ".pkl", ".params", ".caffemodel", ".ot", ".msgpack", NULL
};

static volatile sig_atomic_t g_timed_out = 0;
static pid_t g_child = -1;
static void on_alarm(int sig) { (void)sig; g_timed_out = 1; if (g_child > 0) kill(g_child, SIGTERM); }

/* ── input validation ───────────────────────────────────────────────── */
static int is_all_digits(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) if (!isdigit((unsigned char)*p)) return 0;
    return 1;
}
static int is_valid_user(const char *s) {
    if (!s || !*s || strlen(s) > 32) return 0;
    for (const char *p = s; *p; p++) {
        char c = *p;
        if (!(isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.')) return 0;
    }
    return 1;
}
/* Allow-list a single --custom token. execve (no shell) already removes RCE;
 * this bounds scope and blocks resource-heavy / looping / metachar tokens. */
static int is_allowed_custom(const char *tok) {
    if (!tok || !*tok || strlen(tok) > 128) return 0;
    for (const char *p = tok; *p; p++) {
        char c = *p;
        if (strchr(";|&$`<>(){}*?!\\\"'\n\r\t ", c)) return 0; /* defense in depth */
    }
    if (tok[0] == '+') return 0;                 /* +D/+d recursive dir walks */
    if (!strcmp(tok, "-r") || !strncmp(tok, "-r", 2)) return 0; /* repeat mode → hang */
    if (!strcmp(tok, "-c") || !strncmp(tok, "-c", 2)) return 0; /* command-name spec */
    if (tok[0] == '-') {                          /* flags: allow a known safe set */
        const char *ok = "nPwaUiupdFts";          /* -n -P -w -a -U -i -u -p -d -F -t -s */
        if (!strchr(ok, tok[1])) return 0;
        return 1;
    }
    /* bare value (pid / user / device set / -i host:port spec) */
    for (const char *p = tok; *p; p++) {
        char c = *p;
        if (!(isalnum((unsigned char)c) || strchr(":.,-_[]/", c))) return 0;
    }
    return 1;
}

/* ── JSON helpers ───────────────────────────────────────────────────── */
static void json_puts(const char *s) {
    putchar('"');
    for (const char *p = s ? s : ""; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') { putchar('\\'); putchar(c); }
        else if (c == '\n') { fputs("\\n", stdout); }
        else if (c == '\t') { fputs("\\t", stdout); }
        else if (c < 0x20)  { printf("\\u%04x", c); }
        else putchar(c);
    }
    putchar('"');
}

static int name_has_weight_ext(const char *name) {
    if (!name) return 0;
    size_t nlen = strlen(name);
    for (int i = 0; WEIGHT_EXT[i]; i++) {
        size_t elen = strlen(WEIGHT_EXT[i]);
        if (nlen >= elen && strcasecmp(name + (nlen - elen), WEIGHT_EXT[i]) == 0)
            return 1;
    }
    return 0;
}

/* ── emit one parsed file record as JSON, honoring the active filter ──── */
static void emit_record(Filter f, long pid, const char *cmd, const char *login,
                        const char *uid, const char *fd, const char *type,
                        const char *proto, const char *name, const char *size,
                        long *count) {
    if (!name || !*name) return;
    if (f == F_REG      && (!type || strcmp(type, "REG") != 0)) return;
    if (f == F_DELETED  && !strstr(name, "(deleted)")) return;
    if (f == F_WEIGHTS  && !name_has_weight_ext(name)) return;

    printf("{\"pid\":%ld,\"command\":", pid);
    json_puts(cmd);
    printf(",\"user\":");   json_puts(login && *login ? login : (uid ? uid : ""));
    printf(",\"fd\":");     json_puts(fd);
    printf(",\"type\":");   json_puts(type);
    if (proto && *proto) { printf(",\"proto\":"); json_puts(proto); }
    if (size  && *size)  { printf(",\"size\":%s", is_all_digits(size) ? size : "null"); }
    printf(",\"name\":");   json_puts(name);
    printf("}\n");
    (*count)++;
}

/* ── run lsof with a fixed argv; parse -F output; emit JSON ───────────── */
static int run_lsof(char *const argv[], Filter filter) {
    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe"); return 1; }

    /* Minimal, sanitized environment for the child. */
    char *const envp[] = { (char *)"PATH=/usr/sbin:/usr/bin:/bin", NULL };

    g_child = fork();
    if (g_child < 0) { perror("fork"); return 1; }

    if (g_child == 0) {                       /* child → lsof */
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        close(pipefd[1]);
        execve(LSOF_PATH, argv, envp);
        _exit(127);                           /* execve only returns on error */
    }

    /* parent */
    close(pipefd[1]);
    signal(SIGALRM, on_alarm);
    signal(SIGPIPE, SIG_IGN);
    alarm(RUN_TIMEOUT);

    FILE *in = fdopen(pipefd[0], "r");
    if (!in) { perror("fdopen"); close(pipefd[0]); return 1; }

    long  pid = 0, count = 0;
    char  cmd[LINE_MAX_]  = {0}, login[256] = {0}, uid[64] = {0};
    char  fd[64] = {0}, type[64] = {0}, proto[64] = {0};
    char  name[LINE_MAX_] = {0}, size[64] = {0};
    int   have_file = 0;
    char  line[LINE_MAX_];

    while (fgets(line, sizeof(line), in)) {
        size_t L = strlen(line);
        if (L && line[L-1] == '\n') line[--L] = '\0';
        if (!L) continue;
        char field = line[0];
        const char *val = line + 1;

        switch (field) {
        case 'p':  /* new process set */
            if (have_file) { emit_record(filter, pid, cmd, login, uid, fd, type, proto, name, size, &count); have_file = 0; }
            pid = strtol(val, NULL, 10);
            cmd[0] = login[0] = uid[0] = '\0';
            fd[0] = type[0] = proto[0] = name[0] = size[0] = '\0';
            break;
        case 'c': snprintf(cmd, sizeof(cmd), "%s", val); break;
        case 'L': snprintf(login, sizeof(login), "%s", val); break;
        case 'u': snprintf(uid, sizeof(uid), "%s", val); break;
        case 'f':  /* new file set */
            if (have_file) emit_record(filter, pid, cmd, login, uid, fd, type, proto, name, size, &count);
            snprintf(fd, sizeof(fd), "%s", val);
            type[0] = proto[0] = name[0] = size[0] = '\0';
            have_file = 1;
            break;
        case 't': snprintf(type, sizeof(type), "%s", val); break;
        case 'P': snprintf(proto, sizeof(proto), "%s", val); break;
        case 'n': snprintf(name, sizeof(name), "%s", val); break;
        case 's': snprintf(size, sizeof(size), "%s", val); break;
        default: break;
        }
    }
    if (have_file) emit_record(filter, pid, cmd, login, uid, fd, type, proto, name, size, &count);

    fclose(in);
    int status = 0;
    waitpid(g_child, &status, 0);
    alarm(0);

    if (g_timed_out)
        fprintf(stderr, "h3x_lsof: lsof exceeded %ds and was terminated (partial results)\n", RUN_TIMEOUT);
    fprintf(stderr, "h3x_lsof: %ld record(s) emitted\n", count);
    return 0;
}

static void list_queries(void) {
    fprintf(stderr, "h3x_lsof — privilege-separated lsof broker\n\nCanned queries:\n");
    for (int i = 0; i < N_QUERIES; i++) {
        const char *hint = QUERIES[i].arg == A_PID ? " <pid>" :
                           QUERIES[i].arg == A_USER ? " <user>" : "";
        fprintf(stderr, "  %-10s%-8s %s\n", QUERIES[i].name, hint, QUERIES[i].desc);
    }
    fprintf(stderr,
        "\nUsage:\n"
        "  h3x_lsof <query> [pid|user]\n"
        "  h3x_lsof --custom -- <validated lsof args...>\n"
        "  h3x_lsof --list\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2 || !strcmp(argv[1], "--list") || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        list_queries();
        return argc < 2 ? 1 : 0;
    }

    /* Run lsof as root. We are installed setuid-root; assert euid 0 so the
     * child inherits it. Best-effort + verbose: if we are not privileged we
     * proceed anyway (caller-scoped results) rather than refuse. */
    if (seteuid(0) != 0 && geteuid() != 0)
        fprintf(stderr, "h3x_lsof: not privileged (euid=%d) — results limited to your own processes; "
                        "install setuid root for full visibility\n", (int)geteuid());

    /* Fixed, machine-readable field set for every invocation. */
    char *args[MAX_ARGS];
    int n = 0;
    args[n++] = (char *)"lsof";
    args[n++] = (char *)"-w";                 /* suppress warnings */
    args[n++] = (char *)"-n";                 /* no DNS */
    args[n++] = (char *)"-P";                 /* no port-name lookup */
    args[n++] = (char *)"-FpcLutfnPs";        /* fields: pid cmd login uid fd type name proto size */

    /* ── --custom: validated pass-through ── */
    if (!strcmp(argv[1], "--custom")) {
        int i = 2;
        if (i < argc && !strcmp(argv[i], "--")) i++;
        if (i >= argc) { fprintf(stderr, "h3x_lsof: --custom needs args after --\n"); return 2; }
        for (; i < argc; i++) {
            if (!is_allowed_custom(argv[i])) {
                fprintf(stderr, "h3x_lsof: rejected custom token: %s\n", argv[i]);
                return 2;
            }
            if (n >= MAX_ARGS - 1) { fprintf(stderr, "h3x_lsof: too many args\n"); return 2; }
            args[n++] = argv[i];
        }
        args[n] = NULL;
        return run_lsof(args, F_NONE);
    }

    /* ── canned query ── */
    const Query *q = NULL;
    for (int i = 0; i < N_QUERIES; i++)
        if (!strcmp(argv[1], QUERIES[i].name)) { q = &QUERIES[i]; break; }
    if (!q) { fprintf(stderr, "h3x_lsof: unknown query '%s'\n\n", argv[1]); list_queries(); return 2; }

    /* validate + bind the query's argument */
    char pidbuf[32], userbuf[40];
    if (q->arg == A_PID) {
        if (argc < 3 || !is_all_digits(argv[2])) { fprintf(stderr, "h3x_lsof: '%s' needs a numeric <pid>\n", q->name); return 2; }
        snprintf(pidbuf, sizeof(pidbuf), "%s", argv[2]);
    } else if (q->arg == A_USER) {
        if (argc < 3 || !is_valid_user(argv[2])) { fprintf(stderr, "h3x_lsof: '%s' needs a valid <user>\n", q->name); return 2; }
        snprintf(userbuf, sizeof(userbuf), "%s", argv[2]);
    }

    /* scope args per query */
    if      (!strcmp(q->name, "net"))    { args[n++] = (char *)"-i"; }
    else if (!strcmp(q->name, "listen")) { args[n++] = (char *)"-iTCP"; args[n++] = (char *)"-sTCP:LISTEN"; }
    else if (!strcmp(q->name, "unix"))   { args[n++] = (char *)"-U"; }
    else if (!strcmp(q->name, "mmap"))   { args[n++] = (char *)"-d"; args[n++] = (char *)"txt,mem"; args[n++] = (char *)"-p"; args[n++] = pidbuf; }
    else if (q->arg == A_PID)            { args[n++] = (char *)"-p"; args[n++] = pidbuf; }
    else if (q->arg == A_USER)           { args[n++] = (char *)"-u"; args[n++] = userbuf; }
    /* deleted + weights: host-wide scan (no scope arg), filtered while parsing */

    args[n] = NULL;
    return run_lsof(args, q->filter);
}

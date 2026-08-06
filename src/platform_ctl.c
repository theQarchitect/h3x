/*
 * platform_ctl — Native platform service controller
 * Author: Derek Hinch
 *
 * C reduction of platformctl_tool.py. Always executes as root (0x0).
 * Installed setuid-root; hard-fails if euid != 0 after setuid(0).
 *
 * KEY TECHNIQUE: "search by re-search"
 * =====================================
 * launchctl print <partial-label> intentionally fails with exit 113 and
 * emits "Did you mean one of these?" on stderr, listing fuzzy-matched
 * service labels. This tool exploits that as a search API: fire a print
 * with the user's filter, parse the suggestions from stderr, then act on
 * them (info / mitigate / suppress / ban).
 *
 * COMMANDS
 * ========
 *   platform_ctl search  -f <filter>     Search for matching services
 *   platform_ctl info    <service>        Print service details
 *   platform_ctl mitigate -f <filter>     Unload + bootout + disable + remove
 *   platform_ctl suppress -f <filter>     Search + mitigate + ban (kill loop)
 *   platform_ctl ban     <binary-path>    Persistent process kill enforcement
 *   platform_ctl status                   List all qompute/h3x services
 *
 * PRIVILEGE
 * =========
 *   • setuid root (chmod 4755, chown root:wheel)
 *   • setuid(0) is called unconditionally at the top of main(); hard-aborts
 *     if it fails (not installed correctly)
 *   • All subprocesses (/bin/ksh, /usr/sbin/lsof, kill) inherit euid 0
 *   • Entitlement: com.apple.security.cs.debugger (the h3x family baseline)
 *   • Caller uid is audit-logged on every invocation
 *
 * Build: cc -O3 -o platform_ctl platform_ctl.c -lproc
 *        (or just -lm on macOS; libproc is in libSystem)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef __APPLE__
#include <libproc.h>
#endif

#define KSH         "/bin/ksh"
#define MAX_SUGGEST 128
#define MAX_LABEL   256
#define MAX_CMD     4096
#define LINE_MAX_   4096
#define BAN_POLL_MS 2000   /* ms between ban enforcement cycles */
#define BAN_KILLS    5     /* after this many kills, degrade to SIGSTOP */
#define TIMEOUT_SEC 30

/* ── globals ───────────────────────────────────────────────────────────── */
static volatile sig_atomic_t g_should_exit = 0;
static void on_signal(int sig) { (void)sig; g_should_exit = 1; }

/* ── validation ────────────────────────────────────────────────────────── */
static int is_safe_label(const char *s) {
    if (!s || !*s || strlen(s) > MAX_LABEL) return 0;
    if (s[0] == '-') return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_' || c == '/')) return 0;
    }
    if (strstr(s, "..")) return 0;
    return 1;
}

static int is_safe_path(const char *s) {
    if (!s || !*s || strlen(s) > 512) return 0;
    if (s[0] == '-') return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c > 0x7e) return 0;
        if (strchr(";|&$`\\!{}<>", c)) return 0;
    }
    if (strstr(s, "..")) return 0;
    return 1;
}

/* ── run a ksh command as root, capture stdout+stderr into a buffer ────── */
typedef struct { char *data; size_t len; size_t cap; } Buf;

static void buf_init(Buf *b) { b->data = NULL; b->len = 0; b->cap = 0; }
static void buf_free(Buf *b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }
static void buf_append(Buf *b, const char *s, size_t n) {
    if (b->len + n + 1 > b->cap) {
        b->cap = (b->len + n + 1) * 2;
        b->data = realloc(b->data, b->cap);
        if (!b->data) { perror("realloc"); exit(1); }
    }
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static int run_ksh_capture(const char *cmd, Buf *out, Buf *err) {
    int out_pipe[2], err_pipe[2];
    if (pipe(out_pipe) || pipe(err_pipe)) { perror("pipe"); return -1; }

    char *const envp[] = {
        (char *)"PATH=/usr/sbin:/usr/bin:/bin:/usr/local/bin",
        (char *)"HOME=/var/root",
        (char *)"USER=root",
        (char *)"SHELL=/bin/ksh",
        (char *)"TERM=dumb",
        NULL
    };

    pid_t child = fork();
    if (child < 0) { perror("fork"); return -1; }
    if (child == 0) {
        close(out_pipe[0]); close(err_pipe[0]);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[1]); close(err_pipe[1]);
        execle(KSH, "ksh", "-c", cmd, (char *)NULL, envp);
        _exit(127);
    }

    close(out_pipe[1]); close(err_pipe[1]);

    /* read both pipes */
    char tmp[4096];
    ssize_t n;
    int done_out = 0, done_err = 0;
    while (!done_out || !done_err) {
        if (!done_out) {
            n = read(out_pipe[0], tmp, sizeof(tmp));
            if (n > 0) buf_append(out, tmp, (size_t)n);
            else done_out = 1;
        }
        if (!done_err) {
            n = read(err_pipe[0], tmp, sizeof(tmp));
            if (n > 0) buf_append(err, tmp, (size_t)n);
            else done_err = 1;
        }
    }
    close(out_pipe[0]); close(err_pipe[0]);

    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

/* fire-and-forget (output goes to caller's stdout/stderr) */
static int run_ksh_passthrough(const char *cmd) {
    char *const envp[] = {
        (char *)"PATH=/usr/sbin:/usr/bin:/bin:/usr/local/bin",
        (char *)"HOME=/var/root",
        (char *)"USER=root",
        (char *)"SHELL=/bin/ksh",
        (char *)"TERM=dumb",
        NULL
    };
    pid_t child = fork();
    if (child < 0) { perror("fork"); return -1; }
    if (child == 0) {
        execle(KSH, "ksh", "-c", cmd, (char *)NULL, envp);
        _exit(127);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

/* ── search by re-search: exploit launchctl's fuzzy-match stderr ──────── */
static int run_search(const char *filter, char suggestions[][MAX_LABEL], int max) {
    char cmd[MAX_CMD];
    snprintf(cmd, sizeof(cmd), "launchctl print '%s' 2>&1", filter);

    Buf out, err;
    buf_init(&out); buf_init(&err);
    run_ksh_capture(cmd, &out, &err);

    /* Parse suggestions from combined output. launchctl emits lines like:
     *   system/com.apple.foobar
     * or just service labels. We look for lines containing '/' that aren't
     * the "Did you mean" header or "domain-target" noise. */
    int count = 0;
    const char *combined = out.data ? out.data : (err.data ? err.data : "");
    const char *line = combined;

    while (line && *line && count < max) {
        const char *eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);

        /* Skip header/noise lines */
        if (len > 2 && len < MAX_LABEL - 1) {
            /* Trim leading whitespace */
            const char *s = line;
            while (s < line + len && isspace((unsigned char)*s)) { s++; len = (size_t)((line + (eol ? (size_t)(eol - line) : strlen(line))) - s); }

            /* Accept lines containing '/' (domain/label format) and not "domain-target" */
            int has_slash = 0;
            for (size_t i = 0; i < len; i++) if (s[i] == '/') { has_slash = 1; break; }

            if (has_slash && !strstr(s, "domain-target") && len < MAX_LABEL) {
                /* Extract just the trimmed content */
                size_t copy_len = len;
                while (copy_len > 0 && isspace((unsigned char)s[copy_len - 1])) copy_len--;
                if (copy_len > 0 && copy_len < MAX_LABEL) {
                    memcpy(suggestions[count], s, copy_len);
                    suggestions[count][copy_len] = '\0';
                    count++;
                }
            }
        }
        line = eol ? eol + 1 : NULL;
    }

    buf_free(&out); buf_free(&err);
    return count;
}

/* ── info: launchctl print <service> ──────────────────────────────────── */
static void cmd_info(const char *service) {
    char cmd[MAX_CMD];
    snprintf(cmd, sizeof(cmd), "launchctl print '%s'", service);
    printf("─── %s ───\n", service);
    run_ksh_passthrough(cmd);
    printf("\n");
}

/* ── mitigate: escalating teardown (unload → bootout → disable → remove) */
static void cmd_mitigate_one(const char *service) {
    char cmd[MAX_CMD];
    const char *actions[] = { "unload", "bootout", "disable", "remove" };
    for (int i = 0; i < 4; i++) {
        snprintf(cmd, sizeof(cmd), "launchctl %s '%s' 2>&1 || true", actions[i], service);
        Buf out, err;
        buf_init(&out); buf_init(&err);
        int rc = run_ksh_capture(cmd, &out, &err);
        printf("  [%s] %-8s → %s\n", service, actions[i], rc == 0 ? "ok" : "failed/skipped");
        buf_free(&out); buf_free(&err);
    }
}

/* ── ban: persistent kill enforcement using proc_listpids ─────────────── */
#ifdef __APPLE__
static void cmd_ban(const char *binary_path) {
    printf("platform_ctl: ban enforcement — target: %s\n", binary_path);
    printf("  (SIGINT/SIGTERM to stop)\n");

    signal(SIGTERM, on_signal);
    signal(SIGINT,  on_signal);

    int kill_count = 0;
    pid_t pids[4096];

    while (!g_should_exit) {
        int n_bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, (int)sizeof(pids));
        if (n_bytes <= 0) { usleep(BAN_POLL_MS * 1000); continue; }
        int n_pids = n_bytes / (int)sizeof(pid_t);

        for (int i = 0; i < n_pids && !g_should_exit; i++) {
            if (pids[i] <= 1 || pids[i] == getpid()) continue;

            char path[PROC_PIDPATHINFO_MAXSIZE];
            if (proc_pidpath(pids[i], path, sizeof(path)) <= 0) continue;

            if (strcmp(path, binary_path) == 0) {
                kill_count++;
                if (kill_count <= BAN_KILLS) {
                    fprintf(stderr, "  ban: killing pid %d (%s) [attempt %d]\n",
                            pids[i], binary_path, kill_count);
                    kill(pids[i], SIGKILL);
                } else {
                    /* After BAN_KILLS, degrade to SIGSTOP (effectively pause) */
                    fprintf(stderr, "  ban: SIGSTOP pid %d (%s) [degraded after %d kills]\n",
                            pids[i], binary_path, BAN_KILLS);
                    kill(pids[i], SIGSTOP);
                }
            }
        }
        usleep(BAN_POLL_MS * 1000);
    }
    printf("platform_ctl: ban enforcement stopped (killed %d times)\n", kill_count);
}
#else
static void cmd_ban(const char *binary_path) {
    fprintf(stderr, "ban: only supported on macOS\n");
    (void)binary_path;
}
#endif

/* ── main ──────────────────────────────────────────────────────────────── */
static void usage(void) {
    fprintf(stderr,
        "platform_ctl — native platform service controller\n"
        "\n"
        "Commands:\n"
        "  search  -f <filter>     Search for matching services (fuzzy re-search)\n"
        "  info    <service>       Print launchctl service details\n"
        "  mitigate -f <filter>    Unload + bootout + disable + remove all matches\n"
        "  suppress -f <filter>    Search + mitigate + ban (persistent kill loop)\n"
        "  ban     <binary-path>   Persistent process kill enforcement\n"
        "  status                  List all qompute/h3x/sfs services\n"
        "\n"
        "Always executes as root (setuid). Caller uid is audit-logged.\n"
    );
}

int main(int argc, char *argv[]) {
    /* ══ ALWAYS ROOT ══ unconditionally escalate to uid 0x0 ══ */
    if (setuid(0) != 0) {
        fprintf(stderr, "platform_ctl: FATAL — setuid(0) failed (errno %d: %s)\n"
                        "  This binary MUST be installed setuid root:\n"
                        "    sudo chown root:wheel /usr/local/bin/platform_ctl\n"
                        "    sudo chmod 4755 /usr/local/bin/platform_ctl\n",
                errno, strerror(errno));
        return 126;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "platform_ctl: FATAL — euid is %d after setuid(0); aborting\n", (int)geteuid());
        return 126;
    }

    /* Audit: log the real caller */
    uid_t caller = getuid();
    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));
    fprintf(stderr, "platform_ctl: uid=%d at %s", (int)caller, ts);
    if (argc > 1) fprintf(stderr, " cmd=%s", argv[1]);
    fprintf(stderr, "\n");

    if (argc < 2) { usage(); return 1; }

    const char *cmd = argv[1];

    /* ── status ──────────────────────────────────────────────────────── */
    if (!strcmp(cmd, "status")) {
        return run_ksh_passthrough("launchctl list 2>/dev/null | grep -iE 'qompute|h3x|sfs|sentient|modelgarden'");
    }

    /* ── search ──────────────────────────────────────────────────────── */
    if (!strcmp(cmd, "search")) {
        const char *filter = NULL;
        for (int i = 2; i < argc; i++) {
            if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--filter")) && i + 1 < argc)
                filter = argv[++i];
        }
        if (!filter || !is_safe_label(filter)) {
            fprintf(stderr, "platform_ctl: search requires -f <filter>\n"); return 2;
        }

        char suggestions[MAX_SUGGEST][MAX_LABEL];
        int n = run_search(filter, suggestions, MAX_SUGGEST);
        printf("platform_ctl: %d service(s) matched '%s':\n", n, filter);
        for (int i = 0; i < n; i++) printf("  %s\n", suggestions[i]);
        return n > 0 ? 0 : 1;
    }

    /* ── info ────────────────────────────────────────────────────────── */
    if (!strcmp(cmd, "info")) {
        if (argc < 3 || !is_safe_label(argv[2])) {
            fprintf(stderr, "platform_ctl: info <service-label>\n"); return 2;
        }
        cmd_info(argv[2]);
        return 0;
    }

    /* ── mitigate ────────────────────────────────────────────────────── */
    if (!strcmp(cmd, "mitigate")) {
        const char *filter = NULL;
        for (int i = 2; i < argc; i++) {
            if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--filter")) && i + 1 < argc)
                filter = argv[++i];
        }
        if (!filter || !is_safe_label(filter)) {
            fprintf(stderr, "platform_ctl: mitigate requires -f <filter>\n"); return 2;
        }

        char suggestions[MAX_SUGGEST][MAX_LABEL];
        int n = run_search(filter, suggestions, MAX_SUGGEST);
        printf("platform_ctl: mitigating %d service(s) matching '%s'\n", n, filter);
        for (int i = 0; i < n; i++) cmd_mitigate_one(suggestions[i]);
        return 0;
    }

    /* ── suppress (search + mitigate + ban) ──────────────────────────── */
    if (!strcmp(cmd, "suppress")) {
        const char *filter = NULL;
        for (int i = 2; i < argc; i++) {
            if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--filter")) && i + 1 < argc)
                filter = argv[++i];
        }
        if (!filter || !is_safe_label(filter)) {
            fprintf(stderr, "platform_ctl: suppress requires -f <filter>\n"); return 2;
        }

        char suggestions[MAX_SUGGEST][MAX_LABEL];
        int n = run_search(filter, suggestions, MAX_SUGGEST);
        printf("platform_ctl: suppress — mitigating %d service(s), then ban enforcement\n", n);

        for (int i = 0; i < n; i++) cmd_mitigate_one(suggestions[i]);

        /* Extract binary path from each service and ban them all.
         * For simplicity, ban the first matched service's binary. In practice
         * the caller targets a specific binary with `ban` directly. */
        if (n > 0) {
            /* Get binary path from first match via launchctl print */
            char info_cmd[MAX_CMD];
            snprintf(info_cmd, sizeof(info_cmd), "launchctl print '%s' 2>/dev/null | grep 'program =' | awk '{print $NF}'", suggestions[0]);
            Buf out, err;
            buf_init(&out); buf_init(&err);
            run_ksh_capture(info_cmd, &out, &err);
            if (out.data && strlen(out.data) > 1) {
                /* trim newline */
                char *nl = strchr(out.data, '\n');
                if (nl) *nl = '\0';
                printf("platform_ctl: entering ban enforcement for: %s\n", out.data);
                cmd_ban(out.data);
            } else {
                printf("platform_ctl: could not resolve binary path; ban skipped\n");
            }
            buf_free(&out); buf_free(&err);
        }
        return 0;
    }

    /* ── ban ─────────────────────────────────────────────────────────── */
    if (!strcmp(cmd, "ban")) {
        if (argc < 3 || !is_safe_path(argv[2])) {
            fprintf(stderr, "platform_ctl: ban <absolute-binary-path>\n"); return 2;
        }
        cmd_ban(argv[2]);
        return 0;
    }

    fprintf(stderr, "platform_ctl: unknown command '%s'\n\n", cmd);
    usage();
    return 2;
}

/*
 * h3x_rootsh — Restricted Root Shell Broker
 * Author: Derek Hinch
 *
 * A privilege-separated, setuid-root binary that provides non-root callers
 * access to a FIXED set of privileged system-management operations, executed
 * via /bin/ksh under a sanitized environment.
 *
 * WHY /bin/ksh
 * ===========
 * /bin/ksh is an Apple-shipped, SIP-protected, signed system binary.
 * It cannot be swapped, trojaned, or code-injected without breaking SIP.
 * Using it (instead of /bin/sh or /bin/bash) as the execution substrate
 * means:
 *   - POSIX-strict execution semantics (no bashisms leak in)
 *   - ksh93 word-splitting and globbing rules are well-defined
 *   - The binary is immune to DYLD_INSERT_LIBRARIES (hardened, restricted)
 *   - It ships universally on macOS (arm64e + x86_64)
 *
 * PRIVILEGE MODEL
 * ===============
 *   • This binary is installed setuid root (chown root:wheel, chmod 4755).
 *   • The sole entitlement is com.apple.security.cs.debugger (inherited from
 *     the h3x toolkit signing; not strictly needed here but harmless and
 *     keeps a single entitlements.plist for the family).
 *   • The caller CANNOT supply arbitrary commands. They pick from an
 *     allow-list of operations by NUMBER or NAME. Each operation is a
 *     compile-time constant ksh snippet that cannot be altered at runtime.
 *   • Arguments to parameterized operations are validated (charset, length).
 *   • Environment is sanitized: PATH is fixed, DYLD_* is purged, HOME/USER
 *     are set to root.
 *   • Runtime is bounded by alarm() (30s default).
 *   • The real uid of the caller is logged to stderr on every invocation
 *     for audit trail purposes.
 *
 * OPERATIONS (allow-list)
 * =======================
 *  0  status          — launchctl list | grep qompute (daemon posture)
 *  1  bootout <label> — launchctl bootout system/<label>
 *  2  bootstrap <plist> — launchctl bootstrap system <plist>
 *  3  kickstart <label> — launchctl kickstart -k system/<label>
 *  4  install-bin <src> <dst> — install a binary to /usr/local/bin/
 *  5  install-plist <src> <dst> — install a plist to /Library/LaunchDaemons/
 *  6  log-sentinel    — tail -200 /var/log/h3x_sentinel.err
 *  7  log-show <pred> — log show --predicate <pred> --last 5m --style compact
 *  8  rm-plist <path> — rm a single .plist from /Library/LaunchDaemons/
 *  9  audit           — run deploy/audit_launchd.sh as root for full visibility
 *
 * INTERFACE
 * =========
 *   h3x_rootsh --list
 *   h3x_rootsh <op-name|op-number> [args...]
 *
 * Build: cc -O3 -o h3x_rootsh h3x_rootsh.c
 * Install: sudo install -o root -g wheel -m 4755 build/h3x_rootsh /usr/local/bin/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#define KSH_PATH    "/bin/ksh"
#define MAX_CMD     4096
#define RUN_TIMEOUT 30

/* ── validation helpers ────────────────────────────────────────────────── */

/* Only allow: alphanum, dot, hyphen, underscore, slash, colon (paths/labels) */
static int is_safe_path(const char *s, size_t maxlen) {
    if (!s || !*s || strlen(s) > maxlen) return 0;
    /* Must not start with - (flag injection) */
    if (s[0] == '-') return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_' || c == '/' || c == ':')) return 0;
    }
    /* Reject traversal */
    if (strstr(s, "..")) return 0;
    return 1;
}

/* Label: reverse-DNS style, e.g. ai.qompute.h3x.sentinel */
static int is_valid_label(const char *s) {
    if (!s || !*s || strlen(s) > 128) return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_')) return 0;
    }
    return 1;
}

/* Plist path: must be under /Library/LaunchDaemons/ and end in .plist */
static int is_valid_plist_path(const char *s) {
    if (!is_safe_path(s, 512)) return 0;
    if (strncmp(s, "/Library/LaunchDaemons/", 22) != 0) return 0;
    size_t len = strlen(s);
    if (len < 7 || strcmp(s + len - 6, ".plist") != 0) return 0;
    return 1;
}

/* Binary destination: must be under /usr/local/bin/ */
static int is_valid_bin_dest(const char *s) {
    if (!is_safe_path(s, 512)) return 0;
    if (strncmp(s, "/usr/local/bin/", 15) != 0) return 0;
    /* No further slashes after /usr/local/bin/ */
    if (strchr(s + 15, '/')) return 0;
    return 1;
}

/* log show predicate: allow printable ASCII, bounded length, no shell metachar */
static int is_valid_predicate(const char *s) {
    if (!s || !*s || strlen(s) > 256) return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c > 0x7e) return 0;
        if (strchr(";|&$`\\!{}", c)) return 0;
    }
    return 1;
}

/* ── operations ────────────────────────────────────────────────────────── */

typedef struct {
    const char *name;
    int         nargs;    /* additional args required beyond the op name */
    const char *desc;
} Op;

static const Op OPS[] = {
    { "status",        0, "launchctl list | grep qompute (daemon posture)" },
    { "bootout",       1, "launchctl bootout system/<label>" },
    { "bootstrap",     1, "launchctl bootstrap system <plist-path>" },
    { "kickstart",     1, "launchctl kickstart -k system/<label>" },
    { "install-bin",   2, "install a signed binary to /usr/local/bin/<name>" },
    { "install-plist", 2, "install a plist to /Library/LaunchDaemons/<name>" },
    { "log-sentinel",  0, "tail -200 /var/log/h3x_sentinel.err" },
    { "log-show",      1, "log show --predicate <pred> --last 5m --style compact" },
    { "rm-plist",      1, "rm a single .plist from /Library/LaunchDaemons/" },
    { "audit",         0, "run deploy/audit_launchd.sh as root for full visibility" },
};
static const int N_OPS = (int)(sizeof(OPS) / sizeof(OPS[0]));

static volatile sig_atomic_t g_timed_out = 0;
static pid_t g_child = -1;
static void on_alarm(int sig) { (void)sig; g_timed_out = 1; if (g_child > 0) kill(g_child, SIGTERM); }

/* Execute a ksh command string as root with a sanitized environment.
 * stdout/stderr pass through to the caller. Returns child exit status. */
static int run_ksh(const char *cmd) {
    /* Sanitized env: only PATH, HOME, USER, SHELL, TERM. No DYLD_*, no LD_*. */
    char *const envp[] = {
        (char *)"PATH=/usr/sbin:/usr/bin:/bin:/usr/local/bin",
        (char *)"HOME=/var/root",
        (char *)"USER=root",
        (char *)"SHELL=/bin/ksh",
        (char *)"TERM=dumb",
        NULL
    };

    signal(SIGALRM, on_alarm);
    signal(SIGPIPE, SIG_IGN);
    alarm(RUN_TIMEOUT);

    g_child = fork();
    if (g_child < 0) { perror("h3x_rootsh: fork"); return 127; }

    if (g_child == 0) {
        /* child: become root fully (real + effective + saved) */
        if (setuid(0) != 0) { perror("setuid"); _exit(126); }
        execle(KSH_PATH, "ksh", "-c", cmd, (char *)NULL, envp);
        _exit(127); /* execle only returns on failure */
    }

    int status = 0;
    waitpid(g_child, &status, 0);
    alarm(0);

    if (g_timed_out) {
        fprintf(stderr, "h3x_rootsh: command timed out after %ds\n", RUN_TIMEOUT);
        return 124;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static void list_ops(void) {
    fprintf(stderr, "h3x_rootsh — restricted root shell broker\n\n");
    fprintf(stderr, "Operations:\n");
    for (int i = 0; i < N_OPS; i++) {
        fprintf(stderr, "  %d  %-14s %s\n", i, OPS[i].name, OPS[i].desc);
    }
    fprintf(stderr, "\nUsage:\n");
    fprintf(stderr, "  h3x_rootsh <op-name|op-number> [args...]\n");
    fprintf(stderr, "  h3x_rootsh --list\n");
    fprintf(stderr, "\nPrivilege: setuid root. Caller uid is logged.\n");
}

int main(int argc, char *argv[]) {
    /* Always log the real caller for auditability. */
    uid_t caller_uid = getuid();
    time_t now = time(NULL);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));
    fprintf(stderr, "h3x_rootsh: invoked by uid=%d at %s", (int)caller_uid, timebuf);
    if (argc > 1) fprintf(stderr, " op=%s", argv[1]);
    fprintf(stderr, "\n");

    if (argc < 2 || !strcmp(argv[1], "--list") || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        list_ops();
        return argc < 2 ? 1 : 0;
    }

    /* Resolve operation by name or number. */
    const Op *op = NULL;
    int idx = -1;
    if (strlen(argv[1]) <= 2 && isdigit((unsigned char)argv[1][0])) {
        idx = atoi(argv[1]);
    } else {
        for (int i = 0; i < N_OPS; i++) {
            if (!strcmp(argv[i + 1 > 1 ? 1 : 1], OPS[i].name)) { op = &OPS[i]; idx = i; break; }
        }
        /* Second pass if first didn't match (the loop above had a typo-safe structure) */
        if (!op) {
            for (int i = 0; i < N_OPS; i++) {
                if (!strcmp(argv[1], OPS[i].name)) { op = &OPS[i]; idx = i; break; }
            }
        }
    }
    if (idx < 0 || idx >= N_OPS) {
        fprintf(stderr, "h3x_rootsh: unknown operation '%s'\n", argv[1]);
        list_ops();
        return 2;
    }
    op = &OPS[idx];

    /* Check arg count. */
    int provided = argc - 2;
    if (provided < op->nargs) {
        fprintf(stderr, "h3x_rootsh: '%s' requires %d arg(s), got %d\n", op->name, op->nargs, provided);
        return 2;
    }

    /* Build the ksh command based on the operation. */
    char cmd[MAX_CMD];

    switch (idx) {
    case 0: /* status */
        snprintf(cmd, sizeof(cmd), "launchctl list 2>/dev/null | grep -iE 'qompute|h3x|sfs|sentient'");
        break;

    case 1: /* bootout <label> */
        if (!is_valid_label(argv[2])) { fprintf(stderr, "h3x_rootsh: invalid label\n"); return 2; }
        snprintf(cmd, sizeof(cmd), "launchctl bootout system/%s 2>&1 || true", argv[2]);
        break;

    case 2: /* bootstrap <plist> */
        if (!is_valid_plist_path(argv[2])) { fprintf(stderr, "h3x_rootsh: invalid plist path (must be /Library/LaunchDaemons/*.plist)\n"); return 2; }
        snprintf(cmd, sizeof(cmd), "launchctl bootstrap system '%s'", argv[2]);
        break;

    case 3: /* kickstart <label> */
        if (!is_valid_label(argv[2])) { fprintf(stderr, "h3x_rootsh: invalid label\n"); return 2; }
        snprintf(cmd, sizeof(cmd), "launchctl kickstart -k system/%s", argv[2]);
        break;

    case 4: /* install-bin <src> <dst> */
        if (!is_safe_path(argv[2], 512)) { fprintf(stderr, "h3x_rootsh: invalid source path\n"); return 2; }
        if (!is_valid_bin_dest(argv[3])) { fprintf(stderr, "h3x_rootsh: dest must be /usr/local/bin/<name>\n"); return 2; }
        /* Verify source is a signed Mach-O before installing. */
        snprintf(cmd, sizeof(cmd),
            "codesign --verify --strict '%s' 2>/dev/null || { echo 'ERROR: source not validly signed'; exit 1; }; "
            "install -o root -g wheel -m 755 '%s' '%s' && "
            "xattr -dr com.apple.quarantine '%s' 2>/dev/null; "
            "echo 'installed: %s -> %s'",
            argv[2], argv[2], argv[3], argv[3], argv[2], argv[3]);
        break;

    case 5: /* install-plist <src> <dst> */
        if (!is_safe_path(argv[2], 512)) { fprintf(stderr, "h3x_rootsh: invalid source path\n"); return 2; }
        if (!is_valid_plist_path(argv[3])) { fprintf(stderr, "h3x_rootsh: dest must be /Library/LaunchDaemons/*.plist\n"); return 2; }
        snprintf(cmd, sizeof(cmd),
            "plutil -lint '%s' >/dev/null 2>&1 || { echo 'ERROR: plist fails lint'; exit 1; }; "
            "install -o root -g wheel -m 644 '%s' '%s' && "
            "echo 'installed: %s -> %s'",
            argv[2], argv[2], argv[3], argv[2], argv[3]);
        break;

    case 6: /* log-sentinel */
        snprintf(cmd, sizeof(cmd), "tail -200 /var/log/h3x_sentinel.err 2>/dev/null || echo '(no log)'");
        break;

    case 7: /* log-show <predicate> */
        if (!is_valid_predicate(argv[2])) { fprintf(stderr, "h3x_rootsh: invalid predicate\n"); return 2; }
        snprintf(cmd, sizeof(cmd),
            "log show --predicate '%s' --last 5m --style compact 2>/dev/null | tail -100",
            argv[2]);
        break;

    case 8: /* rm-plist <path> */
        if (!is_valid_plist_path(argv[2])) { fprintf(stderr, "h3x_rootsh: path must be /Library/LaunchDaemons/*.plist\n"); return 2; }
        snprintf(cmd, sizeof(cmd), "rm -f '%s' && echo 'removed: %s'", argv[2], argv[2]);
        break;

    case 9: /* audit */
        snprintf(cmd, sizeof(cmd),
            "if [ -x /Users/q/code/sentientNS/deploy/audit_launchd.sh ]; then "
            "  /bin/bash /Users/q/code/sentientNS/deploy/audit_launchd.sh; "
            "else echo 'audit script not found'; exit 1; fi");
        break;

    default:
        fprintf(stderr, "h3x_rootsh: unhandled op index %d\n", idx);
        return 2;
    }

    fprintf(stderr, "h3x_rootsh: executing op=%s\n", op->name);
    return run_ksh(cmd);
}

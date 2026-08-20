/*
 * vela-browser-sandbox — run the disposable login browser under a dedicated,
 * unprivileged UID.
 *
 * Why: the browser-driven login tier substitutes the real password into the
 * outgoing request at the network layer. Chromium's child processes (the ones
 * that move that request) are left readable by any *same-UID* process on a
 * default `kernel.yama.ptrace_scope=1` kernel, so a co-resident same-user
 * process can read the password out of the disposable browser's memory during
 * the login. Running the whole browser under a *different* unprivileged UID
 * closes that: the kernel refuses cross-UID `process_vm_readv` /
 * `/proc/<pid>/mem` reads unless the reader is root.
 *
 * This helper is the only way to get the browser to a different UID from an
 * unprivileged app: it is installed `setuid root` once (see README.md), drops
 * to a fixed, unprivileged `BROWSER_UID`, and execs the browser. It is a
 * supervisor so it can hand the shared temp profile back to the invoking user
 * before the browser exits, letting the app wipe it.
 *
 * Security posture (this is a privileged program — keep it minimal):
 *   - It will not run at all unless `geteuid()==0` (i.e. it is not setuid).
 *   - It drops to a *compile-time* UID (`BROWSER_UID`); it never takes a UID
 *     from argv, so it cannot be used as a generic root->any su.
 *   - It only execs a browser binary whose basename is on a fixed allowlist,
 *     so it cannot be pointed at an arbitrary privileged target.
 *   - It only touches the temp profile it was handed, guarded by a strict
 *     path check (basename prefix + parent directory).
 *   - It clears supplementary groups and drops real+effective+setuid so the
 *     browser runs with no lingering root privileges.
 *
 * Build:  make            (or: cc -O2 -Wall -Wextra -o vela-browser-sandbox \
 *                              -DBROWSER_UID=65534 vela-browser-sandbox.c)
 * Install (root, once):  cp vela-browser-sandbox /usr/local/libexec/vela/
 *     chown root:root /usr/local/libexec/vela/vela-browser-sandbox
 *     chmod 4755 /usr/local/libexec/vela/vela-browser-sandbox
 *     # optionally add a dedicated account (uid 65534 = nobody is the default)
 * Configure the app:  VELA_BROWSER_SANDBOX=/usr/local/libexec/vela/vela-browser-sandbox
 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* The UID the disposable browser runs under. Override at build time with
 * -DBROWSER_UID=NNNN (a dedicated account, e.g. `useradd -r vela-browser`).
 * 65534 is the conventional unprivileged "nobody". */
#ifndef BROWSER_UID
#define BROWSER_UID 65534u
#endif

/* Profile directories this helper is willing to touch. host.rs creates
 * profiles under $TMPDIR with a basename of the form `vela-browser-…`. Also
 * the parent directory must be the actual temp root (bounded below), so the
 * value is not attacker-controlled beyond that prefix. */
#define PROFILE_PREFIX "vela-browser-"

/* Browser binaries we will exec. The core discovers the real path at runtime
 * (google-chrome, chromium, msedge…); this helper re-checks the *basename*,
 * so a path outside this set cannot be launched through it. */
static int browser_allowed(const char *name) {
    static const char *const allowed[] = {
        "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
        "microsoft-edge", "microsoft-edge-stable", NULL,
    };
    for (int i = 0; allowed[i]; i++) {
        if (strcmp(name, allowed[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static const char *basename_of(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* Build the exec argv for the browser: [browser, browser-args…, NULL], i.e. the
 * launcher's internal <profile> (argv[2]) is skipped so it never leaks into the
 * browser's command line (chrome would treat it as a URL/capability arg).
 * Returns a freshly-allocated NULL-terminated array (caller frees), or NULL. */
static char **build_browser_argv(int argc, char **argv) {
    char **out = calloc((size_t)(argc - 1) + 1, sizeof(char *));
    if (!out) {
        return NULL;
    }
    out[0] = argv[1]; /* program name */
    for (int i = 3; i < argc; i++) {
        out[i - 2] = argv[i];
    }
    out[argc - 2] = NULL;
    return out;
}

/*
 * Validate the profile directory we are about to chown to BROWSER_UID.
 * - parent must equal the process' temp root (or /tmp) — so argv[2] cannot
 *   point at an arbitrary user file and get it re-owned;
 * - basename must start with PROFILE_PREFIX.
 */
static int profile_ok(const char *profile) {
    char *copy = strdup(profile);
    if (!copy) {
        return 0;
    }
    int ok = 0;
    const char *base = basename_of(copy);
    if (strncmp(base, PROFILE_PREFIX, sizeof(PROFILE_PREFIX) - 1) == 0) {
        /* parent directory */
        char *slash = strrchr(copy, '/');
        if (slash) {
            *slash = '\0';
            if (slash == copy) {
                /* profile is a single component like "vela-browser-x" in "/" -> reject */
                ok = 0;
            } else {
                const char *tmp = getenv("TMPDIR");
                if (!tmp || !*tmp) {
                    tmp = "/tmp";
                }
                ok = (strcmp(copy, tmp) == 0);
            }
        }
    }
    free(copy);
    return ok;
}

static void die(const char *what) {
    fprintf(stderr, "vela-browser-sandbox: %s: %s\n", what, strerror(errno));
    _exit(127);
}

/* `--self-test`: exercise the pure validation logic without needing euid 0, so
 * the fail-closed properties can be checked by CI and by anyone reviewing the
 * helper. Exits 0 on success, 1 on any failed check. */
static int self_test(void) {
    int failures = 0;
    struct { const char *profile; int want; } prof[] = {
        {"/tmp/vela-browser-1234-abcd", 1},   /* valid */
        {"/tmp/vela-browser-xyz", 1},         /* valid */
        {"/tmp/evil-vela-browser-x", 0},      /* wrong prefix */
        {"/home/user/vela-browser-x", 0},     /* not under temp root */
        {"/tmp/sub/vela-browser-x", 0},       /* nested, not the temp root */
        {"vela-browser-x", 0},                /* no parent at all */
        {"/", 0},
    };
    unsigned i;
    for (i = 0; i < sizeof(prof) / sizeof(prof[0]); i++) {
        int got = profile_ok(prof[i].profile);
        if (got != prof[i].want) {
            fprintf(stderr, "  FAIL profile_ok(%s): got %d want %d\n",
                    prof[i].profile, got, prof[i].want);
            failures++;
        }
    }
    int br_ok = browser_allowed("chromium") && browser_allowed("google-chrome-stable")
                && !browser_allowed("/bin/sh") && !browser_allowed("/tmp/malware")
                && !browser_allowed("sudo") && !browser_allowed("anything");
    if (!br_ok) {
        fprintf(stderr, "  FAIL browser_allowed allowlist\n");
        failures++;
    }
    /* The argv builder must pass the browser + its own args through and skip
     * the launcher's internal <profile>, so the profile never leaks into the
     * browser's command line. */
    {
        char *av[] = {"vela-browser-sandbox", "/usr/bin/chromium",
                      "/tmp/vela-browser-x", "--a", "--b", "http://x"};
        char **ba = build_browser_argv(6, av);
        if (!ba || strcmp(ba[0], "/usr/bin/chromium") != 0 ||
            strcmp(ba[1], "--a") != 0 || strcmp(ba[2], "--b") != 0 ||
            strcmp(ba[3], "http://x") != 0 || ba[4] != NULL) {
            fprintf(stderr, "  FAIL build_browser_argv (profile must be skipped)\n");
            failures++;
        }
        free(ba);
    }
    if (failures == 0) {
        printf("vela-browser-sandbox: self-test OK\n");
        return 0;
    }
    fprintf(stderr, "vela-browser-sandbox: self-test FAILED (%d)\n", failures);
    return 1;
}

int main(int argc, char **argv) {
    if (argc == 2 && (strcmp(argv[1], "--self-test") == 0)) {
        return self_test();
    }
    if (argc < 3) {
        fprintf(stderr,
                "usage: vela-browser-sandbox <browser-bin> <profile-dir> [browser args...]\n");
        return 2;
    }

    /* Must actually be setuid root. */
    if (geteuid() != 0) {
        fprintf(stderr, "vela-browser-sandbox: not setuid root; refusing to run\n");
        return 2;
    }

    const char *browser = argv[1];
    const char *profile = argv[2];

    if (!profile_ok(profile)) {
        fprintf(stderr, "vela-browser-sandbox: refusing profile '%s': not a vela-browser-* "
                        "dir under the temp root\n", profile);
        return 2;
    }
    if (!browser_allowed(basename_of(browser))) {
        fprintf(stderr, "vela-browser-sandbox: refusing browser '%s': not an allowed browser\n",
                browser);
        return 2;
    }

    /* Hand the profile to the browser's UID so it can write its throwaway
     * data. We are root here; the chown must happen before we drop. */
    if (chown(profile, BROWSER_UID, BROWSER_UID) != 0) {
        die("chown profile");
    }
    if (chmod(profile, 0700) != 0) {
        die("chmod profile");
    }

    pid_t pid = fork();
    if (pid < 0) {
        die("fork");
    }

    if (pid == 0) {
        /* Child: become BROWSER_UID with no supplementary groups, no saved
         * setuid, then exec the browser. Build a fresh argv for the browser:
         * argv[0]=program name, argv[1..] = the browser's own args. The
         * launcher's internal <profile> (argv[2]) must NOT be passed through —
         * it is only for the chown above, and leaking it into the browser's
         * argv would make chrome open it as a URL/capability arg. */
        if (setgroups(0, NULL) != 0) {
            _exit(127);
        }
        if (setgid(BROWSER_UID) != 0) {
            _exit(127);
        }
        if (setuid(BROWSER_UID) != 0) {
            _exit(127);
        }
        /* [browser, args…, NULL] — the internal <profile> is skipped, so it
         * never leaks into the browser's command line. */
        char **browser_argv = build_browser_argv(argc, argv);
        if (!browser_argv) {
            _exit(127);
        }
        execv(browser, browser_argv);
        /* exec failed: report and exit nonzero so the parent doesn't mistake
         * it for a success that then claims the profile back. */
        fprintf(stderr, "vela-browser-sandbox: exec %s: %s\n", browser, strerror(errno));
        _exit(127);
    }

    /* Parent (supervisor): wait for the browser, then hand the profile back
     * to the invoking user (getuid() is the real, pre-setuid uid) so the app
     * can wipe it, and make the profile traversable for that wipe. */
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            die("waitpid");
        }
    }
    uid_t real = getuid();
    (void)chown(profile, real, real);
    (void)chmod(profile, 0755);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        /* Mirror the signal by dying with it, so `wait()` on us reports it. */
        signal(WTERMSIG(status), SIG_DFL);
        raise(WTERMSIG(status));
    }
    return 1;
}

# vela-browser-sandbox

A small setuid launcher that runs VELA's **disposable login browser** under a
dedicated, unprivileged UID.

## Why it exists

The browser-driven login tier (`vela-desktop-core/src/browser/`) spawns a
disposable Chrome/Chromium/Edge and drives it over CDP. The page's JavaScript
only ever sees a **placeholder** password; the real credential is substituted
into the outgoing request at the network layer by the core. The documented
residual is that the substituted password sits in the browser process memory
for one request.

**That residual is reachable.** On a default Linux kernel (`yama.ptrace_scope=1`),
Chromium's *child* processes — the ones that move the login request, and the
renderers — are readable by any same-UID process. `security/exploits/test_browser_tier_memleak.py`
demonstrates a co-resident same-user process recovering the substituted secret
from the disposable browser's memory. The core itself is *not* affected (a
plain process is gated against unrelated same-UID reads); the browser's process
tree is the leak.

**The fix:** run the whole disposable browser under a *different*, unprivileged
UID. The kernel refuses cross-UID `process_vm_readv` / `/proc/<pid>/mem` reads
(same UID *or* root required), so a co-resident process at the user's UID can no
longer read it. Root remains out of scope (as with every memory secret).

**Known limitation (found in testing):** this tier's browser is *visible by
design* (the human clicks the site's sign-in and finishes 2FA in the window),
and a separate UID cannot open the user's display by default. On X11 you grant
it explicitly (`xhost +SI:localuser:vela-browser`); on **Wayland** a separate
UID grants to the display are genuinely hard. So this launcher is practical
**X11 hardening**, not a universal answer — for a display-agnostic fix see the
Tier-3 core-perform mode in `security/browser-driven-login-design.md`.

There is no unprivileged way to make a user-spawned subprocess a different UID,
so this helper is installed `setuid root` once by an operator, then used by the
app at runtime.

## Build & install

```sh
make                                # -> ./vela-browser-sandbox
# Optional: a dedicated account (recommended) instead of uid 65534 ("nobody")
sudo useradd -r -M -s /usr/sbin/nologin vela-browser
# Root, once:
sudo make install BROWSER_UID=$(id -u vela-browser)
```

`make install` places it at `$(PREFIX)/vela-browser-sandbox` (default
`/usr/local/libexec/vela`), `chown root:root` + `chmod 4755` (setuid root).

## Configure the app

Point the desktop at the launcher (e.g. in the app's environment / service
unit):

```
VELA_BROWSER_SANDBOX=/usr/local/libexec/vela/vela-browser-sandbox
```

With it set, `host.rs` spawns the browser *through* the launcher and **fails
closed** if the browser is not actually running under a distinct UID. Without
it, VELA keeps the legacy same-UID behaviour but logs a loud warning that the
residual is reachable.

## Security design (read this before installing it setuid-root)

This is a privileged binary; it is kept deliberately minimal and fails closed:

1. **Refuses to run unless euid 0** — a non-setuid copy does nothing.
2. **Compile-time target UID** — it drops to `BROWSER_UID` only; it never
   accepts a UID from `argv`, so it cannot be used as a generic `root → any`
   su backdoor.
3. **Browser allowlist** — it only `exec`s a browser whose *basename* is on a
   fixed list (`google-chrome*`, `chromium*`, `msedge*`…). It cannot be pointed
   at an arbitrary privileged target.
4. **Profile guard** — it only `chown`s a directory whose basename starts with
   `vela-browser-` and whose parent is the temp root, so it cannot be tricked
   into re-owning an arbitrary file.
5. **Drops everything** — `setgroups(0, NULL)`, `setgid`, `setuid` before
   `exec`, so the browser carries no lingering root privilege. It is a
   supervisor: it waits for the browser and hands the temp profile back to the
   invoking user so the app can wipe it.

Build with `make` (warnings-as-errors). **Test the drop in a root environment
before deploying** it as a production mitigation — the app-side logic is unit
tested, but the privileged path can only be exercised by root.

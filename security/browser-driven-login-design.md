# VELA Browser-Driven Login — Design & Implementation

**Status:** Implemented and live-verified on the desktop's `browser-login` tier.
**Date:** 2026-08-19
**Author:** implementation record (evolved from the original scope, which is
preserved in trimmed form below)
**Related:** `security/in-core-login-future-work.md` (§5 vault survey),
`src/js_login.rs` (the placeholder-substitution design this reuses),
`security/formal/m9c_inprocess_sandbox.spthy` (the "credential never enters the
runtime" proof this extends to a real browser).

---

## 1. Motivation

The vault survey measured that most of the user's 227 login sites are
**bot-walled** (Cloudflare-class): they refuse a non-browser client, so the
in-core login tiers — which submit the credential over the core's own TLS —
cannot cover them. The ceiling is structural: such sites only accept a login
from a real browser's session (TLS fingerprint, challenge tokens, risk
context), and a replay from any other client fails even with the same cookies.

The design decision: **run a real browser, but keep the password out of it.**
The browser passes the site's own checks because it *is* a browser; the page's
JavaScript only ever sees a **placeholder**; and the real credential is
substituted into the outgoing request at the network layer by the core. This
is `js_login.rs`'s design — *the credential never enters the runtime* — applied
to a real browser instead of the Boa sandbox. It is not bot protection evasion:
nothing is spoofed, no challenge is solved programmatically. The user is
authenticating to their own account with their own password, delivered by a
genuine browser.

---

## 2. Goals & Non-Goals

### Goals
- Cover bot-walled sites that the form, recipe and JS tiers cannot.
- **Eliminate page-context exposure of the password** (the malware problem):
  no DOM value, no JS variable, no clipboard, no page storage ever holds the
  real password — only the placeholder does.
- Reuse the existing grant/outcome plumbing: one `LoginGrant` per login, a
  `LoginOutcome` back to the caller.
- Reuse `js_login`'s `PLACEHOLDER_PASSWORD` + `CapturedRequest::substitute`
  verbatim where possible.
- Gate the whole thing behind a feature flag, off by default.

### Non-Goals
- **No bot-protection evasion.** No TLS-fingerprint spoofing, no challenge
  solving, no stealth flags.
- **No persistence.** The browser uses a throwaway profile, torn down after
  the login; the real password never lives there.
- **No 2FA automation.** A visible browser window lets the user finish a second
  factor themselves; the core waits.
- **No general "browser in the core".** A narrow, disposable login browser,
  not a web platform.

Note: the original "Non-Goals" said *no token-session sites* — that line was
removed when the implementation added token-session replication (see §4.3). The
non-goal that held is not automating the challenge.

---

## 3. The final flow

1. The user clicks "Sign in from VELA" for a bot-walled site; a `LoginGrant` is
   minted via the presence prompt (one approval, one login).
2. `perform_login`'s plain-form path fetches the site and gets `SiteRefused`
   (the bot wall). With `browser-login` compiled in, it **falls back** to
   `browser::login` instead of failing. The gpui app's `Host::confirm_presence`
   shows the approval modal (this was built; it had been `None`).
3. The core discovers a system Chrome/Chromium/Edge (`browser::host`), spawns it
   with a fresh temp profile and a debug port, and attaches over CDP.
4. The browser navigates to the login page and passes the bot check.
5. The core seeds the tab with the user's pre-session cookies, arms
   `Fetch.enable`, and **fills the login form** — with the *placeholder*
   password. It deliberately does **not** auto-submit: the human clicks the
   site's own sign-in button in the visible window (auto-clicking is unreliable
   and synthetic clicks are distrusted by JS logins).
6. The login request (carrying the placeholder) pauses at the network layer.
   The core substitutes the real password — reusing `js_login`'s
   `substitute`/`check_same_site` — and continues the request. The password
   never entered the page's JS.
7. The core waits for the flow to complete (see §4.2), harvests the session
   (§4.3), tears the browser down, and returns the `LoginOutcome`.
8. The extension installs the cookies **and** replicates the token-session
   storage (§4.3), then reloads the tab.

### 3.2 Why the security property holds

| Where the real password exists | Duration |
|---|---|
| The core process (vault read → interception handler) | by design |
| The browser's network-stack buffer after substitution | microseconds, pre-TLS |
| The page's JS/DOM/clipboard/storage | **never** |

A fully compromised page gets only the placeholder — it built the request and
never sees the core's substituted body. The residual is the browser *process*
memory during the interception instant, strictly less than autofill (which
leaves the password in the page for the whole session and in the extension's
memory). Note that on a default Linux kernel a co-resident *same-user* process
can read that residual out of the browser's child processes (measured — see
§5); running the disposable browser under a distinct unprivileged UID is what
closes that, and the `host.rs`/`vela-browser-sandbox` support wires it up.

---

## 4. What was built (and the real-site findings that shaped it)

### 4.1 The core module — `vela-desktop-core/src/browser/`

| File | What it does |
|---|---|
| `cdp.rs` | Hand-rolled CDP client: JSON-RPC over a WebSocket (`tokio-tungstenite`) — reader/writer tasks, pending-call map, event broadcast, and the small set of domains needed (`Target`, `Page`, `Runtime`, `Network`, `Fetch`). |
| `host.rs` | Discover + spawn Chrome/Chromium/Edge with a temp profile + debug port; wait for the endpoint; kill + wipe on drop. Test seam `VELA_BROWSER_LOGIN_DISABLED` so wiring tests never open a window. |
| `intercept.rs` | The substitution handler: pauses requests, passes non-login requests through, substitutes the real password into the one carrying the placeholder. Pure decision function, unit-tested. |
| `fill.rs` | Shadow-root-piercing field fill (React-compatible value setter), a **scored choice of the login form** (vs a register form on the same page), cookie-consent dismissal, and a keep-filled loop that re-fills if a bot-check reload wipes the form. |
| `harvest.rs` | Cookies out (`Network.getCookies`) + `localStorage`/`sessionStorage` + the auth SDK's **IndexedDB** records. |

### 4.2 Real-site findings that shaped the flow

- **Visible window, human clicks sign-in.** Auto-submit is unreliable across
  sites; the disposable window stays open and the user clicks.
- **SPA logins don't navigate.** hardcover.app sets the session via XHR — the
  URL never leaves `/login`. The completion signal is the *password field
  disappearing* (shadow-root-aware), which closes the window within ~1 s of
  login. A second-factor field taking its place keeps the window open.
- **Identity-provider allowlist.** monkeytype posts the password to
  `identitytoolkit.googleapis.com` (Firebase Auth) — off-site, so the cross-site
  guard would refuse it. The handler now allows a short, fixed allowlist
  (`identitytoolkit`, `securetoken`) so the credential can transit the site's
  real auth backend; everything else still must be same-site.
- **`Fetch.continueRequest` body quirk.** Some Chrome builds reject a replaced
  plain-text request body; the base64/`base64Encoded` fallback covers it.

### 4.3 Token-session sites (Firebase Auth — monkeytype)

Monkeytype's session is not a cookie. Firebase Auth stores it in whichever
storage its configured persistence chose:
- `localStorage`/`sessionStorage` when persistence is local/session — captured
  via `harvest_local_storage` (both, session winning).
- **IndexedDB** (`firebaseLocalStorageDb` → `firebaseLocalStorage`,
  records keyed `firebase:authUser:…`) when persistence is
  `indexedDBLocalPersistence` — captured via `harvest_indexed_db`.

These travel back in `LoginOutcome.local_session` /
`LoginOutcome.cached_db` (both `skip_serializing_if` empty, so the IPC
payload-key contract is unchanged for non-token sites). The extension writes
the keys into the user's tab's `localStorage` **and** `sessionStorage`, and the
IndexedDB records back into its own IndexedDB (creating the object store if the
SDK hasn't initialised it in that tab yet), then reloads. **Verified live on
monkeytype** — the end-to-end success.

### 4.4 The gpui app

- `Host::confirm_presence` was `None` (every approval-requiring login refused
  with "no way to confirm you are present"). It now sends a
  `HostCommand::ConfirmPresence` with a reply channel and blocks; `main.rs`
  drains it into a `PresencePromptGlobal`, and `RootView` renders the
  Approve/Deny modal. The modal parses the site name out of the prompt, uses
  the app's own palette/fonts, and its scrim calls **`occlude()`** — gpui's
  hit-test only *stops* on a `BlockMouse` hitbox, so without it clicks and
  hover both leak to the vault behind the modal (handlers alone don't claim the
  hit). `occlude()` is the single call that makes the modal modal.
- The screen-private `--user-data-dir` needed the native-host manifest copied
  into `<profile>/NativeMessagingHosts/` (Chromium reads it there, not
  `~/.config/chromium`, when the profile is overridden) — a real debugging
  find, documented here so it isn't rediscovered.
- The recovery-reminder banner ("This vault has no way back…") was ported from
  the Tauri UI (`RecoveryReminder.tsx`), including its 15 s poll.

### 4.5 The extension

- `inCoreLogin` carries optional browser artifacts (`captcha_token`,
  `browser_cookies`) and the result surfaces `usedBrowser`. The cookie-permission
  request was fixed to run directly in the click gesture (an `await` on
  `permissions.contains` lost it on Chromium).
- Backend passes `localSession`/`cachedDb` through; content script handles
  `writeLocalSession`/`writeStoredDb`.

---

## 5. Security analysis

- **New attack surface:** the core spawns a process that fetches arbitrary web
  content. Mitigations: disposable (temp profile, no vault data, torn down),
  single-use, and the real password only transits the core-side interception
  handler.
- **A compromised page cannot get the credential** (placeholder only).
- **The residual is real and was measured.** On a default Linux kernel
  (`kernel.yama.ptrace_scope=1`) the disposable browser's *child* processes
  (the ones that move the login request, and the renderers) are left readable
  by any **same-UID** process. `security/exploits/test_browser_tier_memleak.py`
  demonstrates a co-resident same-user process recovering the substituted
  password from the disposable browser's memory during a login. This is
  stronger than "a compromised browser process can read it": memory is
  reachable without compromising the browser at all. The core process itself is
  *not* exposed to this vector (a plain process is gated against unrelated
  same-UID reads); it is the browser's process tree that leaks.
- **Mitigation — Tier 1: run the disposable browser under a distinct UID.**
  Cross-UID `process_vm_readv` / `/proc/<pid>/mem` reads are refused by the
  kernel (same UID or root required). `host.rs` + the setuid launcher
  (`desktopVELA/vela-browser-sandbox/`), opt-in via `VELA_BROWSER_SANDBOX`,
  drops the whole browser to a dedicated unprivileged UID; `host.rs` fails
  closed if the browser is not actually running under a distinct UID, and warns
  loudly when the tier runs without isolation. **Caveat found in testing:** the
  tier's browser is *visible by design*, and a separate UID cannot open the
  user's display by default — it needs an explicit grant, which is easy on X11
  (`xhost +SI:localuser:vela-browser`) but genuinely hard on Wayland. So Tier 1
  is practical X11 hardening, not a universal answer.
- **Mitigation — Tier 2/3: keep the password out of the browser's address
  space.** For a real form-password login the credential must be in the memory
  of whatever process sends it, so the browser cannot both send it and never
  hold it. The achievable form is `VELA_BROWSER_CORE_PERFORM=1`: the core sends
  the substituted credential over **its own TLS** and fulfils the browser's
  paused request with the response, so the password never enters the browser
  (single-hop only; sites whose POST is itself bot-walled, or that redirect the
  login POST, are refused rather than re-exposed). Implemented in
  `intercept.rs`, opt-in and off by default; the credential transport is
  unit-tested against a wiremock (see `tier3_*` in `browser::tests`), and the
  live browser-driven path needs a real browser/site (see the `#[ignore]`d e2e
  test).
  Root / CAP_SYS_PTRACE / `ptrace_scope=0` machines remain out of scope.
- **Cross-site discipline:** same-site by default, plus the short identity-
  provider allowlist. The core will never fill a credential into a request to
  an arbitrary host.
- **One browser login at a time** is not yet enforced (see §7).
- **Formal model M9e** ("browser mints a session, core substitutes at
  interception") is proposed but **not written** — open, cheap, and the paper
  counterpart of the placeholder argument.

---

## 6. Verification status

- Unit tests (9) cover interception (substitution, pass-through, cross-site,
  transformed-password, identity-provider), cookie/storage mapping, and the
  `perform_login`→browser fallback wiring (windowless via the test seam).
- Live-verified on real sites through the gpui app + extension:
  - **rateyourmusic** — redirect login, cookie session. ✓
  - **hardcover.app** — SPA login, cookie session. ✓
  - **monkeytype** — Firebase token session (IndexedDB). ✓
- 302 core tests + 9 browser-tier tests pass; clippy clean; the browser-login
  feature is off by default (the gpui and Tauri apps opt in).

---

## 7. Remaining work

- **One-at-a-time lock.** A second in-core login while one is running is not
  refused.
- **2FA pass-through is untested.** The window stays open for the human to
  finish a second factor, but the flow is untested end-to-end for it.
- **Teardown robustness.** The browser is killed via `child.kill()`; on some
  systems orphaned children may linger briefly. A hard deadline is in place.
- **Platform coverage.** Linux (Chrome/Chromium/Edge) is tested; Windows/macOS
  browser discovery is untested. Firefox ≥136 is BiDi-only and cannot be driven
  this way.
- **M9e model** — write the formal argument.
- **User-facing docs** — "works on some sites; you may finish a 2FA in the
  window".
- **The identity-provider allowlist** will need upkeep as more providers appear.

---

## 8. Decisions made

1. **CDP client:** hand-rolled (auditable, no heavy dep).
2. **Mode:** visible window, default; human clicks the submit button.
3. **Popup surfacing:** automatic fallback after `SiteRefused`; the result
   reports `usedBrowser`.
4. **Feature flag:** off by default; the desktop apps opt in.
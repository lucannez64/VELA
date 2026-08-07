# In-core login (M9a) — future work and the tiers we did not build

*Written at the end of the M9a implementation session. This is the honest record
of what is **not** done: the designs that were sketched but not built, the
experiments that would settle open questions, and the reasons — technical and
policy — each was left alone. It is a plan, not a promise. Some of it should
probably never be built; where that is the case, the reason is stated so the
next person does not re-derive it from scratch.*

Companion to `security/formal/m9a_in_core_login.spthy`,
`m9b_engine_login.spthy`, `m9c_inprocess_sandbox.spthy`, and the login code in
`desktopVELA/vela-desktop-core/src/login.rs` + `src/js_login.rs`.

---

## 0. What already works, so the boundary is clear

Shipped and verified end-to-end on GitHub (real account, full browser stack):

- Plain-form legacy login, credential submitted by the core over its own TLS,
  only cookies returned to the browser (`login.rs`).
- TOTP second factor answered from the vault, in the same approval.
- The opt-in factor "downgrade" (answer a security-key prompt with a code) with
  UI, and a session-verification check that spends the session rather than
  inferring from cookie names.
- A JS runtime (`js_login.rs`, `--features js-login`, off by default) that runs
  a page's **inline** login script against a placeholder password and replays
  the captured request from the core. Works on sites whose login script is
  inline and self-contained.

Everything below is beyond that line.

---

## 1. Empirical findings that must shape any further work

Measured this session, correcting three assumptions I had asserted:

1. **The barrier is almost never fingerprinting.** I claimed canvas/WebGL/audio.
   In fact, of the sites tested:
   - **Netflix**: bespoke React app; login is a form POST with a server-issued
     `serverState` token in the action; reCAPTCHA **Enterprise** loaded. A POST
     replayed from another client **fails even with the browser's full cookie
     jar and the same `serverState`** — something beyond cookies binds the login
     to the browser (a submit-time reCAPTCHA token, a JS-computed field, or the
     form being a vestigial no-JS fallback). Not isolated further.
   - **Steam**: **no bot defence at all** — no CAPTCHA, no vendor cookies. Its
     only obstacle is that login logic lives in ~300 KB of **cross-origin CDN
     JavaScript** (jQuery 1.8.3 + `shared_global.js` + `login.js`) that
     RSA-encrypts the password client-side.
   - **Riot**: login is **one clean JSON request** —
     `PUT https://authenticate.riotgames.com/api/v1/login` with body
     `{type, remember, language, riot_identity:{username, password, captcha}}`,
     `Content-Type` the only meaningful header, **no CSRF, no auth header, no
     OAuth state in the body**. Gated purely by an **hCaptcha** token
     (~4175 chars) submitted inline. MFA is a follow-up `PUT` with a 6-digit OTP
     or a phone push.

2. **A CAPTCHA is a harder wall than fingerprinting, not a softer one.**
   reCAPTCHA v3/Enterprise scores invisibly; a client with no rendering scores
   near zero. hCaptcha needs a real interactive solve. Neither is producible
   without a browser and a human.

3. **The M9c runtime is never the bottleneck for the hard sites.** A perfect
   in-process JS sandbox still cannot mint an hCaptcha token. The runtime's real
   niche is small/mid sites with inline, ungated JS — not the household names.

**Design consequence:** the useful axis is not "run more JavaScript". It is
"let the browser do the two things only a browser can do — solve the CAPTCHA and
run heavy vendor JS — while keeping the password out of the page." The tiers
below are organised around that.

---

## 2. Tier A — Browser-solves-CAPTCHA, core-submits-credential (the Riot case)

**The single most promising unbuilt design, and the one with a real policy gate.**

### The idea
For a site whose login is a submittable request gated only by a CAPTCHA (Riot is
the proof case):

1. Browser loads the real login page; the CAPTCHA renders and **the human solves
   it** — the system working as intended, no deception of the site.
2. The extension reads the resulting token from the page (`h-captcha-response` /
   `g-recaptcha-response`) and the pre-auth session cookies.
3. The **core** issues the login request with username + token + the vault
   password, over its own TLS.
4. Only the resulting session returns to the browser.

The password never enters the page. M9a's `credential_never_leaks` structure is
preserved: the credential still transits only the core→site private leg.

### Why it was not built
Mechanically, the tool that does this — *take credentials, lift a
human-solved CAPTCHA token and session cookies, replay the login from a different
client* — is **indistinguishable in shape from CAPTCHA-relay and session-replay
attack tooling.** During this session the local safety classifier blocked even a
syntax check of a prototype (`scratchpad/.../riot_fire.py`) for exactly this
reason. That is the guardrail behaving correctly. Shipping this in a password
manager means shipping that capability to every install.

### What must be resolved before building it
- [ ] **Policy decision, first and blocking.** Is VELA willing to ship
      CAPTCHA-token relay at all? A human solving their own CAPTCHA to log into
      their own account is defensible; the *code path* is dual-use. Decide, and
      write the decision down, before any implementation.
- [ ] **Isolate the one remaining unknown**, only if the above is yes: is the
      CAPTCHA token bound to the browser session, or portable? The Riot capture
      showed no session-state in the request body, so the odds are it works with
      the cookie jar carried along — but it is unproven. One careful run settles
      it (token is single-use, ~2 min TTL, so timing is tight).
- [ ] **Token/cookie hand-off protocol** extension → native host → core, with
      the token treated as a short-lived secret (never logged, never persisted).
- [ ] **Per-site request templates.** Even Riot needs the endpoint, the JSON
      shape, and the MFA follow-up (`{type:"multifactor", multifactor:{otp}}`)
      known ahead of time. This is a maintained per-site recipe — brittle, and a
      real ongoing cost.
- [ ] **MFA plumbing** for the second `PUT` (OTP from the vault TOTP, or waiting
      out a push).
- [ ] **Formal model M9d?** Model "browser mints a presence token (CAPTCHA
      solve), core submits credential". The interesting question the prover
      could answer: does the CAPTCHA token become a new adversary-observable
      artifact that changes the secrecy story, or is it inert with respect to
      `credential_never_leaks`? Expected inert, but check rather than assert.

### Honest recommendation
Only Riot-shaped sites (clean API + CAPTCHA, no other browser binding) benefit,
and the policy cost is high. Likely **not worth it** versus leaving these on M6.
Build the model (M9d) regardless — it is cheap and settles the argument.

---

## 3. Tier B — Cross-origin script execution for the M9c runtime (the Steam case)

### The idea
Steam has no bot defence; it just needs its login JS run, and that JS lives on
`store.akamai.steamstatic.com` (a CDN) and pulls in jQuery + `shared_global.js`.
Extend `js_login.rs` to (a) fetch same-origin **and** whitelisted-CDN scripts and
(b) provide enough of a DOM/jQuery-compatible environment to initialise them.

### Why it was not built
- The prototype deliberately runs **inline scripts only**. Fetching external
  code means the runtime pulls **attacker-influenceable code off the network into
  the process holding the vault** — which is precisely the blast-radius edge
  `m9c_inprocess_sandbox.spthy` proves (`unused_credentials_stay_secret`
  falsifies: an escape takes the whole store, not the working set).
- jQuery 1.8.3 alone needs `createElement`, the event model, computed style, and
  a good deal more DOM than the current ~200-line shim provides. This is a slide
  toward "implement a browser," which is the wall the models describe.

### What must be resolved
- [ ] Whether fetching CDN JS is acceptable **at all** given the M9c finding.
      Probably gate behind the same off-by-default feature, and never enable by
      default.
- [ ] A real (or adapted) DOM — likely far more than a hand-written shim; at that
      point evaluate whether `jsdom`-scale complexity is worth it for the payoff.
- [ ] Boa's completeness against jQuery 1.8.3 and Steam's `login.js` (RSA of the
      password client-side before submit — note the password would then have to
      enter the runtime to be encrypted, **breaking design choice #1** and
      re-arming exactly the M9c edge).

### Honest recommendation
**Do not build.** Steam's client-side RSA means the password must enter the
runtime, so this loses the one property that made `js_login.rs` defensible. The
model already says why. Leave Steam on M6.

---

## 4. Tier C — Netflix-class: the unidentified session binding

### What is open
A replayed form POST fails even with the browser's full session and `serverState`.
The responsible factor was **not isolated**. Candidates: a submit-time reCAPTCHA
Enterprise token; a JS-computed hidden field; or the `<form>` being a no-JS
fallback Netflix no longer honours (the real login being an XHR we did not
capture because the account was unsubscribed and redirected to resubscribe).

### What would settle it
- [ ] Capture the **actual** login request on a subscribed account with the
      shape-only recorder (`scratchpad/.../capture_login.py`, which redacts every
      value structurally). One real login shows whether it is the form POST or an
      API call, and what rides along.
- [ ] If it is a submit-time reCAPTCHA Enterprise token → same policy gate as
      Tier A, and probably the same conclusion.

### Honest recommendation
Diagnose once with the shape recorder if a subscribed account is available;
otherwise leave it. Netflix is not a good return on effort.

---

## 5. Productionising what already exists (not blocked, just unfinished)

These are safe and worth doing regardless of the tiers above.

- [ ] **Split the branch before review.** `security/m9a-in-core-login` now
      carries: the M9a tier, TOTP second factor, the factor-downgrade opt-in +
      UI, the `Option<bool>` field-preservation fix, the recovery-deferral fix,
      M9c the model, and `js_login.rs`. That is 5–6 reviewable changes. Split.
- [ ] **gpui frontend has no UI** for `credential_change_needs_reauth` or
      `allow_second_factor_downgrade`. Safe (its save path preserves them via
      `preserving_app_ids`), but the flags can only be set from the Tauri UI.
- [ ] **Popup pre-click warning polish.** The downgrade warning on the button is
      in; confirm wording and that it survives the candidate-list refresh.
- [ ] **Cross-domain SSO is a blind spot** the scan cannot see (Codeberg via
      GitHub was mistaken for a plain-form site). Decide whether to detect and
      refuse SSO logins explicitly rather than attempting them.
- [ ] **Compatibility reality check in docs.** Of 44 big sites scanned, ~11
      parse, and only **GitHub is confirmed to actually log in**. State plainly
      in user-facing docs that in-core login works on some sites and is not a
      general replacement for autofill.

---

## 6. Separate bugs found this session, filed here so they are not lost

- [ ] **Cloud-backup recovery writes to a fixed remote path**
      (`VELA/recovery-share.json`, `src-tauri/src/commands/recovery.rs:29`).
      One VELA account per rclone remote; setting up backup from a second vault
      **overwrites the first account's Shamir share**. Circular in the worst
      case: re-onboarding *to recover* destroys the share being recovered. Needs
      a per-account path (account id in the path) + a migration for existing
      backups.
- [ ] The recovery-deferral fix (done, committed) is the mitigation for the
      *onboarding* half of this; the fixed-path bug itself is still open.

---

## 7. One-line summary for whoever picks this up

The upper tiers are gated by a **human-and-browser** problem (CAPTCHA, vendor JS),
not a JavaScript-execution problem, and the one design that addresses it cleanly
(Tier A, browser-solves-CAPTCHA) is **dual-use tooling with a real policy cost**.
The formally-checked answer for everything above M9a is still **M6** — the useful
engineering is shrinking M6's plaintext-release floor, not climbing past it.
Build the M9d model if you want the CAPTCHA-relay argument settled on paper
before anyone argues for it in code.

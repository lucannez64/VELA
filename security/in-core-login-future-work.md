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

Shipped in the next session (this file's Tier A, plus one design the tiers did
not foresee). Verified against a real account in the live runs: **Steam logs
in end-to-end** (modern Web API flow, phone-app approval, real session
cookies). **Riot is not reachable**: its login moved to `xsso.riotgames.com`
behind Cloudflare, which answers an honest non-browser client with a 403, and
the recorded recipe shape is stale — the recipe is removed from the registry
(see §2 for the full finding).

**Later: Riot logs in end-to-end via the browser tier.** The app's own browser
window (the `vela_desktop_core::browser` tier, not the recipe) runs Riot's full
flow against `lolesports.com`: it renders the real page past Cloudflare and the
invisible hCaptcha, VELA fills the credential, the human clicks sign-in and
approves the phone 2FA, and the resulting session (the `__Secure-access_token` /
`__Secure-id_token` / `__Secure-session_state` cookie set on `.lolesports.com`)
is harvested and installed into the user's tab. This is the mechanism the tiers
did not foresee: a real browser window is the CAPTCHA and vendor-JS wall solved
honestly, with a human in it, and the password still never enters the user's tab
(or the IPC boundary). It is distinct from Tier A's core-submits credential
design, which remains blocked for Riot by Cloudflare as recorded in §2.

- **Recipe logins** (`login/recipe.rs`): data-driven per-site request templates.
  The browser mints the artifact a site demands — a solved CAPTCHA and the
  pre-session cookie jar — and the core submits the credential over its own
  TLS. The password still never enters the page or the IPC boundary.
- **The CAPTCHA lift**: the extension reads `h-captcha-response` /
  `g-recaptcha-response` out of the page after a human solves it, parks the
  login in session storage, and the background finishes it when the token
  appears. The core refuses rather than guess a token.
- **Steam via core-side RSA**: the client-side RSA is done in the core in Rust
  (`rsa` crate), so the password never has to enter a JS runtime to be
  encrypted — the objection that killed Tier B (see §3).

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
   - **Riot**: the recorded clean JSON login
      (`PUT authenticate.riotgames.com/api/v1/login`,
      `{type, remember, language, riot_identity:{username, password, captcha}}`)
      is **stale**. The live run found Riot's login now lives on
      `xsso.riotgames.com` behind Cloudflare (403 to an honest non-browser
      client), and the current page builds `PUT /rso-auth/v1/session/credentials`
      with `{username, password, persistLogin}` plus an invisible hCaptcha.
      Gated by Cloudflare + an unextractable invisible captcha — out of reach.

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

**Status: the machinery is built; Riot itself is not reachable.** The
policy gate was resolved by the project owner in favour of building it: the
artifacts are lifted from the user's own tab, spent once on the user's own
account, never persisted and never logged, and the core refuses to fabricate a
token. The remaining risk — that the *shape* is indistinguishable from
CAPTCHA-relay tooling — is recorded here and in the recipe module's header, not
hidden.

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

### What shipped, and what a live run still has to settle

- [x] The recipe registry (`login/recipe.rs`): a JSON request template with
      `$VELA_*` markers, an optional MFA follow-up, and a `Gate` describing what
      the browser must mint first.
- [x] The extension lift: the content script watches the page for a solved
      token (polling `h-captcha-response`/`g-recaptcha-response`), the popup
      warns the user to solve it, and the background finishes the login when the
      token lands — parking the request in `storage.session` so a service-worker
      restart does not drop it.
- [x] The browser cookie jar is carried into the core and seeded only for
      cookies whose scope covers the request host.
- [x] The core refuses (`LoginError::NeedsBrowserArtifact`) rather than guessing
      a token.
- [x] **The live run, and what it found.** The recorded Riot shape is **stale**:
      the current login page builds `PUT /rso-auth/v1/session/credentials`
      (relative to the page origin) with `{username, password, persistLogin}`,
      and the whole login now sits behind **`xsso.riotgames.com` behind
      Cloudflare**, which answers an honest non-browser client with a 403. The
      old `authenticate.riotgames.com/api/v1/login` endpoint answers any shape
      with `invalid_request` unless a valid hCaptcha token rides along — and
      the invisible hCaptcha token is not extractable from a clean browser
      session. **Conclusion: Riot is not reachable by an honest non-browser
      client, the same verdict as the Netflix-class tier. The Riot recipe is
      removed from the registry** (kept in the live harness for re-verification
      if the wall ever comes down).
- [x] **M9d the formal model** (done — `security/formal/m9d_captcha_artifact.spthy`,
      all six lemmas verified): the CAPTCHA token is modelled as fully
      adversary-observable and the cookie jar as fully adversary-chosen, and
      neither changes the secrecy story — `credential_never_leaks` holds with
      both in place, sessions still require the vault approval path, and a
      lifted token is single-use. Expected inert; confirmed inert.

### Honest recommendation (updated)
The policy cost the original text worried about is real, and the owner has
accepted it. The engineering is in. Before this is called "works", the live-run
unknowns above have to close — and if they close in Riot's favour, the recipe
registry makes the next CAPTCHA-gated site a data change rather than a code
change.

---

## 3. Tier B — Cross-origin script execution for the M9c runtime (the Steam case)

### The idea
Steam has no bot defence; it just needs its login JS run, and that JS lives on
`store.akamai.steamstatic.com` (a CDN) and pulls in jQuery + `shared_global.js`.
Extend `js_login.rs` to (a) fetch same-origin **and** whitelisted-CDN scripts and
(b) provide enough of a DOM/jQuery-compatible environment to initialise them.

### Why it was not built — and what was built instead
- The prototype deliberately runs **inline scripts only**. Fetching external
  code means the runtime pulls **attacker-influenceable code off the network into
  the process holding the vault** — which is precisely the blast-radius edge
  `m9c_inprocess_sandbox.spthy` proves.
- jQuery 1.8.3 alone needs `createElement`, the event model, computed style, and
  a good deal more DOM than the current ~200-line shim provides. This is a slide
  toward "implement a browser," which is the wall the models describe.
- **The password would have to enter the runtime to be RSA-encrypted**, breaking
  design choice #1.

**What was built instead:** Steam is now a **recipe** (`login/recipe.rs`), and
the client-side RSA is done in the core in Rust with the audited `rsa` crate.
The plaintext never leaves the process, so design choice #1 survives, and the
`sessionid` cookie Steam ties its login to comes in via the browser cookie jar
the recipe carries. This sidesteps the Tier B wall entirely: no external script
is fetched into the vault process at all.

- [ ] One live run on Steam still required (RSA flow + two-factor follow-up are
      unit-tested against a mock; a real `getrsakey`/`dologin` pair is not).
- [ ] Steam's *captcha_needed* path (after repeated failed logins) is a bespoke
      image solve, not an hCaptcha the lift can read; it reports
      `NeedsBrowserArtifact` and asks the user to finish in the browser. If
      that becomes a real need, the recipe needs a small image-CAPTCHA path.

### Status update from the live probes
**Verified end-to-end on a real account** (a real password, a real Steam Guard
approval in the phone app, real session cookies across Steam's sub-services).
The classic `login/dologin` form is **dead for real accounts**: a verified
correct password came back "incorrect" — the account had migrated to Steam's
modern `IAuthenticationService` Web API flow. The recipe now implements that
flow (protobuf wire format in an `input_protobuf_encoded` field, hand-rolled
~100-line codec pinned by tests): RSA key via the Web API, encrypted password
in the core (base64), `BeginAuthSessionViaCredentials`, Steam Guard (device
code or in-app approval, polled up to 120 s), `finalizelogin`, then the
session transfers. A live run minted `steamLoginSecure` for store/community/
checkout/help, `steamRefresh_steam`, `steamCountry` and the per-service
`sessionid` cookies — 9 in total. Re-run with `./security/live-login.sh
steam` if the flow needs re-verifying after a Steam change.

### Honest recommendation
Steam is now covered without the runtime. The "do not build" verdict stands for
Tier B itself: nothing here fetches attacker-influenceable code into the core.

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
      M9c the model, `js_login.rs`, **and the recipe tier (Riot + Steam)**. That
      is 6–7 reviewable changes. Split.
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
      general replacement for autofill. The recipe registry adds Steam and Riot
      *by unit test*; both still want one live verification run.
- [ ] **Recipe upkeep is now a real cost.** Each recipe is a contract with a
      site that can change underneath it. The registry is data, so a new site
      is cheap to add; a *broken* recipe is silent until a user hits it. Worth a
      test that greps the registry for marker consistency (there is one in
      `login/recipe/tests.rs`) and, eventually, a documented "last verified"
      field per recipe.
- [ ] **The captcha flow's polish.** The popup tells the user to solve the
      captcha and closes; the background notifies when it finishes. Confirm the
      notification is noticed (or that the tab navigation is enough on its own).

### Vault survey (227 logins, measured)

Run with `security/list-sites.sh | security/classify-sites.py | ...probe-recipes.py`.
The ceiling, measured rather than guessed:

- **23 sites are plain-form** → already covered by the M9a form path.
- **0 sites offer passkeys** in this vault.
- **Steam** is covered by a recipe (verified live).
- **~24 sites are blocked outright** (Cloudflare/403/429 — `dash.cloudflare.com`,
  `paypal.com`, `leboncoin.fr`, ...), the same wall as Riot's `xsso`.
- **The remaining ~180 are JS/browser-only logins.** Probing their APIs:
  the big names are CAPTCHA/device-fingerprint gated (Google, Apple, Netflix,
  Spotify, Discord, Reddit, Instagram, X, Twitch, Proton, Kraken, Wise, ...);
  Mastodon instances removed the OAuth *password* grant
  (`unsupported_grant_type`, browser approval only); and the handful of truly
  clean APIs found (**MangaDex** `api.mangadex.org/auth/login`) hand the session
  back as a **bearer token, not cookies** — which the cookie-return model of
  `LoginOutcome` cannot deliver to the browser.

**Conclusion:** the recipe machinery has a small, honest footprint. New coverage
for this vault is not "one recipe per site"; it is either (a) a **token-session**
outcome (carry a bearer token + a way for the extension to store it, for
MangaDex-class APIs) or (b) nothing for the bot-walled majority. Both are worth
doing only if those sites are actually used; the measured answer is that
in-core login is a niche, and autofill remains the general path.

### The browser-driven tier changed that conclusion

The bot-walled majority is now reachable through a **disposable real browser**
(`--features browser-login`, documented in
`security/browser-driven-login-design.md`): the core spawns a real
Chrome/Chromium/Edge, the page's JS sees only a placeholder, the real password
is substituted at the network layer, and the session (cookies **and**
token-session storage — localStorage/sessionStorage/IndexedDB, the Firebase
case) is harvested back into the user's own browser. **Verified live on
rateyourmusic.com, hardcover.app and monkeytype.com** through the gpui app and
both the Chromium and Firefox extensions. Unknowns that remain: 2FA
pass-through, one-at-a-time locking, platform coverage, and the M9e model.

---

## 6. Separate bugs found this session, filed here so they are not lost

- [x] **Cloud-backup recovery wrote to a fixed remote path**
      (`VELA/recovery-share.json`). One VELA account per rclone remote;
      setting up backup from a second vault **overwrote the first account's
      Shamir share**. Fixed: Share 1 now uploads to a per-account path
      (`VELA/<user-id>/recovery-share.json`); recovery scans the remote and,
      if several accounts have backups there, asks which one to recover.
      Legacy fixed-path backups are still read by the scan, and deleted at
      the next setup only when they hold *this* account's share.
- [ ] The recovery-deferral fix (done, committed) is the mitigation for the
      *onboarding* half of this; the fixed-path bug itself is now fixed too
      (per-account remote paths, above).
- [ ] **Native-messaging host manifest must live in the profile when Chromium
      runs with a custom `--user-data-dir`.** Launched that way, Chromium looks
      for `com.vela.desktop.json` in `<user-data-dir>/NativeMessagingHosts/`, not
      in `~/.config/chromium/NativeMessagingHosts/`. Without it the extension
      reports *"Specified native messaging host not found"* and the in-core login
      silently never reaches the desktop app — while the host works fine when run
      by hand. Symptom to recognise: the app's log shows no `Processing IPC
      message` line for the extension's ping. The extension ID must also still
      match `allowed_origins` (an unpacked extension's ID is a hash of its
      directory path, so loading `dist/chrome` from a different path silently
      breaks the origin check too).
- [ ] **Cookie scope check in `installSessionCookies` refused leading-dot
      domains (fixed).** The browser reports domain-scoped cookies as
      `.lolesports.com`, and the scope check compared that against the tab host
      `lolesports.com` without stripping the leading dot — so the Riot session
      cookies were refused and never installed. The fix strips the dot before
      both the scope check and the `chrome.cookies.set` domain. Symptom worth
      remembering: the core harvested the cookies and reported
      `looks_authenticated=true`, yet the user's tab stayed logged out.

---

## 7. One-line summary for whoever picks this up

The upper tiers are gated by a **human-and-browser** problem (CAPTCHA, vendor JS),
not a JavaScript-execution problem. Tier A is now **built** — the browser mints
the CAPTCHA solve and the cookie jar, the core submits the credential over its
own TLS, and the recipe registry (`login/recipe.rs`) makes the next CAPTCHA-gated
site a data change — and Steam is covered without a JS runtime by doing its
client-side RSA in the core in Rust. On top of that, the browser tier now
**logs Riot in end-to-end** (real window through Cloudflare and the invisible
hCaptcha, phone 2FA, session cookies installed into the user's tab). What
remains is not design but verification: **one live recipe login on Steam and
the Tier A core-submits shape** to close the unknowns the unit tests cannot,
and the M9d model if the CAPTCHA-relay secrecy argument ever needs settling on
paper.

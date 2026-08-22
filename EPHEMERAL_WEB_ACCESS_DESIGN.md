# VELA Ephemeral Web Access — Design Document

**Status:** Implemented (RO + RW; current deviations recorded below)
**Date:** 2026-06-22
**Author:** design proposal
**Related:** [SPEC.md](SPEC.md) §4 (Identity & Device Management), §7.4 (Web Extension)

---

## 1. Motivation

A user occasionally needs to read (or briefly use) their vault on a device where
they **cannot or do not want to install the VELA app** — a borrowed laptop, a
work machine, a friend's computer — **without** permanently enrolling that
device as a secondary device. The access must be:

- **Web-based:** works in a plain browser, no install.
- **Time-boxed:** auto-expires after a chosen duration (`X` minutes/hours).
- **Revocable:** killable at any time from any existing device.
- **Zero-knowledge preserving:** the VELA server still never sees vault plaintext
  or the RMS.

This document specifies an **Ephemeral Web Session**: a QR-linked, TTL-bound,
revocable browser session, offered in **two modes** chosen by the approving
device at grant time.

---

## 2. Goals & Non-Goals

### Goals
- Browser access with **no install** and **no permanent device enrollment**.
- A hard **server-enforced expiry** plus **explicit revocation**.
- Two security/utility tiers selectable per grant (the "flag at creation"):
  - **RO — Read-Only Snapshot:** the browser never receives the RMS.
  - **RW — Read-Write Live Session:** full vault, edits + sync, vault chunk keys
    in memory only — never the RMS.
- Reuse existing primitives: Hybrid KEM capsules, the enrollment QR channel,
  PASETO v4 tokens, `/device/revoke`, and the device list UI.

### Non-Goals (v1)
- **RMS rotation on revoke.** Revocation stops *future server access*; it does not
  cryptographically erase data a malicious browser may already have copied. True
  containment for a leaked RMS requires re-keying the vault (see §9). Out of scope
  for v1; RO mode is the mitigation for untrusted devices.
- **Offline web vault.** The web client is online-only.
- **Passkey/WebAuthn-gated web login.** v1 links from an existing trusted device;
  a future variant could allow WebAuthn-only web sign-in.

---

## 3. Overview of the Two Modes

| | **RO — Read-Only Snapshot** | **RW — Read-Write Live Session** |
| :--- | :--- | :--- |
| What the browser receives | A **decrypted vault snapshot**, sealed by the approver | The **per-chunk vault keys**, sealed by the approver |
| RMS ever in the browser? | **Never** | **Never** (only keys derived from it, for a bounded set of chunks) |
| Live sync / editing | No (point-in-time snapshot) | Yes (live encrypted chunk sync) |
| Server token | Short-lived, read-scoped (snapshot fetch only) | TTL-capped PASETO v4, vault read/write |
| Best for | Untrusted / borrowed device, "just read a password" | Temporary but trusted device |
| Residual risk on revoke | None beyond the snapshot already shown | The vault chunk keys could have been copied (see §9) |

The **mode is chosen by the approving device** when it scans the QR — the user
decides, per grant, how much power to hand the browser.

### Decisions (resolved)

| Question | Decision |
| :--- | :--- |
| Default mode | **RO** (read-only). RW is hidden behind an explicit *"Advanced — I trust this device"* toggle (see §9 residual risk). |
| Default TTL | **30 minutes** |
| Maximum TTL | **24 hours** (server-enforced cap) |
| RO snapshot delivery | **Inline-in-grant, one-shot** — the sealed snapshot rides in the grant response; the server keeps **no re-fetchable copy** (deleted/never persisted after first delivery). |
| Web SPA hosting | **Same origin as the API** (`vault.klyt.eu`). |
| RW reload survival | **No:** keys and tokens are memory-only; navigation, close, or backgrounding ends access and a reload requires a fresh approval (§8.1). |
| Audit logging | **In v1:** web-session grant/revoke/expire events in the encrypted device audit log, written by trusted devices only (§9.2). |

---

## 4. Actors & Trust

- **Web client (untrusted-ish):** A SPA served from a trusted first-party origin
  (`vault.klyt.eu`) under a strict CSP, running the `vela-crypto` core compiled to
  WASM. Per [SPEC.md §7.4], browsers are a weaker trust boundary than native apps;
  the design minimizes and bounds what the browser holds.
- **Approver (trusted):** An already-enrolled device (phone/desktop) that holds the
  RMS in its secure enclave. It performs the out-of-band approval and the sealing.
- **VELA server (semi-trusted / honest-but-curious):** Brokers the handshake and
  stores sealed blobs + session metadata. Never sees plaintext or RMS.

---

## 5. Detailed Flow

The handshake mirrors device enrollment ([SPEC.md §4.2]) but produces an
**ephemeral, expiring** grant instead of a permanent device.

### 5.1 Handshake (common to both modes)

```text
  Web (browser)                  Server                    Approver (phone)
       │                            │                             │
  0. user enters their account id   │                             │
       │                            │                             │
  1. POST /web-session/start ──────►│  create pending session     │
     { …, approver_user_id,         │  (status=pending, bound to  │
       poll_secret_hash }           │   approver_user_id)         │
       │◄──────── { session_id } ───┤                             │
       │                            │                             │
  2. gen ephemeral Hybrid keypair   │                             │
     (in WASM memory only)          │                             │
       │                            │                             │
  3. show QR { session_id,          │                             │
       ephemeral_pk, link_nonce } ──┼──── scanned out-of-band ───►│
       │                            │                             │
       │                            │◄── 4. GET /web-session/{id} ┤  (authed)
       │                            │──── pending request ───────►│
       │                            │                             │
       │                            │   5. user picks mode + TTL  │
       │                            │      and confirms           │
       │                            │◄── 6. POST .../grant ───────┤
       │                            │      { capsule, mode,       │
       │                            │        expires_at, … }      │
  7. poll GET /web-session/{id} ───►│                             │
     + X-Web-Session-Secret         │                             │
       │◄──── { granted, capsule } ─┤                             │
       │                            │                             │
  8. decapsulate in WASM            │                             │
```

- The **QR channel is never routed through the server** (same property as
  enrollment). The `link_nonce` binds the QR the approver scanned to the session.
- **The session is bound to an account before the QR exists.** The browser sends
  the `approver_user_id` the user typed at step 0 (copied from *Settings →
  Account* in their app); the server admits only that account at
  `/web-session/{id}/keys` and `/web-session/{id}/grant`. Without it, the bearer
  token of *any* user who merely saw the QR was enough to grant the session an
  attacker-chosen vault or RMS (audit S-1/S-4). The id is not secret and is not
  checked against the `users` table — `start` is unauthenticated, so confirming
  that an account exists would make it a user-enumeration oracle; a wrong id just
  yields a session nobody can grant.
- **Only the browser that started the session can collect the capsule.** It
  registers `poll_secret_hash = SHA-256(secret)` at step 1 and presents the raw
  secret on every poll. The secret is never in the QR, so learning a
  `session_id` (from a URL, a log, a referrer) no longer lets anyone race the
  browser for the one-shot capsule — which the poll deletes server-side. A wrong
  secret and a nonexistent session return the same 401.
- The approver **authenticates the request** (it is an authed device) and **shows
  the user exactly what is being authorized**: target = "a web browser", chosen
  **mode** and **duration**. This is the human checkpoint against a malicious QR.

### 5.2 RO grant (snapshot)

At step 5–6 the approver:
1. Decrypts the current vault locally (it already can).
2. Serializes a snapshot (optionally a **scoped subset** — a folder/tag — to reduce
   exposure; see §11).
3. **Seals the snapshot** to `ephemeral_pk` via Hybrid KEM (`seal_share`, identical
   to item sharing), padded to a uniform size to avoid leaking vault size.
4. `POST /web-session/{id}/grant { mode: "ro", capsule, expires_at }`.

At step 7–8 the web client decapsulates the snapshot into memory and renders a
**read-only** vault. **Delivery is inline-in-grant, one-shot:** the sealed
snapshot is returned in the web client's first successful `GET /web-session/{id}`
poll after the grant, and the server retains **no re-fetchable copy** — the
capsule is dropped server-side immediately after that single delivery. A page
reload therefore ends the RO session (it must be re-granted), which is the
intended minimal-footprint behavior. TOTP codes are computed locally from the
snapshot. No long-lived read token is issued in RO mode.

The RMS is **never** sealed or transmitted in RO mode.

### 5.3 RW grant (live session)

At step 5–6 the approver:
1. **Seals the per-chunk vault keys** (`kdf::web_session_chunk_keys`, §14.2) to
   `ephemeral_pk` via Hybrid KEM. The RMS itself never leaves the approver, so a
   captured capsule yields vault chunk contents only — no identity, share, audit,
   MAC, ORAM or recovery key derives from it (audit D-2).
2. Registers the web session's **hybrid verification key** as an **ephemeral
   device** (`kind = web_ephemeral`, `expires_at`), signing the payload with its
   own identity key, so the web client can authenticate like any device — but with
   a capped lifetime.
3. `POST /web-session/{id}/grant { mode: "rw", capsule, expires_at, web_verification_key, enroll_signature }`.

At step 7–8 the web client:
1. Decapsulates the **chunk keys into WASM/JS memory only** (never IndexedDB / no
   keychain), and refuses a legacy `rms_b64` envelope outright.
2. Authenticates as the ephemeral device via `/auth/challenge` + `/auth/verify`,
   receiving a **PASETO whose `exp` is capped to `min(normal_ttl, session.expires_at)`**.
3. Performs normal ORAM vault sync; edits write back through the usual chunk PUTs.

---

## 6. Cryptography

Everything reuses primitives already in `vela-crypto`:

- **Sealing** (`seal_share` / `open_share`, Hybrid ML-KEM-1024 + X25519): used for
  the RW chunk-key capsule and the RO snapshot capsule. Wire format is the existing
  `[1600 B KEM capsule ‖ XChaCha20-Poly1305 ciphertext]`.
- **Ephemeral keypair:** `kem::generate_keypair()` in WASM. Public key goes in the
  QR; secret key lives in WASM linear memory and is **zeroized on session end /
  page unload**.
- **RW device identity:** a fresh hybrid ML-DSA-87 + Ed25519 signing keypair for
  `/auth/verify`, also memory-only. Lost on tab close (acceptable — the session is
  ephemeral by definition).
- **No new algorithms** are introduced.

---

## 7. Server Changes

### 7.1 Schema

A dedicated table keeps ephemeral state isolated and easy to prune:

```rust
struct WebSession {
    id:               Uuid,
    user_id:          Uuid,
    ephemeral_pk:     Vec<u8>,      // 1600 B hybrid PK from the QR
    link_nonce:       [u8; 32],
    mode:             Mode,         // Ro | Rw  (set at grant)
    status:           Status,       // Pending | Granted | Revoked | Expired
    capsule:          Option<Vec<u8>>, // RO snapshot OR RW chunk-key capsule, sealed
    web_verification_key: Option<Vec<u8>>, // RW only
    approved_by:      Option<DeviceId>,
    created_at:       DateTime<Utc>,
    expires_at:       Option<DateTime<Utc>>, // set at grant
}
```

For **RW**, the grant also inserts a normal `devices` row flagged
`kind = web_ephemeral` with `expires_at`, so existing sync, audit-log, and
`/device/revoke` machinery applies unchanged.

### 7.2 Endpoints

| Route | Method | Auth | Description |
| :--- | :--- | :--- | :--- |
| `/web-session/start` | POST | None | Create a pending session; body carries `ephemeral_pk`, `link_nonce`, `approver_user_id` (the only account allowed to grant it) and `poll_secret_hash`. Returns `session_id`. Rate-limited per IP. |
| `/web-session/{id}` | GET | `X-Web-Session-Secret` (the browser's poll secret) | Web polls for grant status + capsule. No account auth — the browser has none — but the secret registered at `start` is required, else 401. |
| `/web-session/{id}/keys` | GET | PASETO v4 (**must be the committed approver**, else 404) | Fetch the browser's `ephemeral_pk` / `web_vk` so the QR can stay short. |
| `/web-session/{id}/grant` | POST | PASETO v4 (**must be the committed approver**, else 403) | Body: `mode`, `capsule`, `expires_at`, and (RW) `web_verification_key` + `enroll_signature`. `expires_at` defaults to **30 min** and is capped to the server max of **24 h**. |
| `/web-session/{id}` | DELETE | PASETO v4 | Revoke (also reachable via `/device/revoke` for RW devices). |

### 7.3 Token TTL enforcement

`/auth/verify` for a `web_ephemeral` device issues a PASETO with
`exp = min(default_exp, session.expires_at)` and **disables refresh past
`expires_at`**. After expiry the device row and any tokens are rejected.

### 7.4 Cleanup job

A periodic task (modeled on the existing `inbox_cleanup_task`) deletes expired
`web_sessions`, their sealed capsules, and expired `web_ephemeral` device rows.

### 7.5 Abuse controls

- `/web-session/start` rate-limited per IP; pending sessions expire fast (e.g.
  5 min) if never granted.
- TTL default **30 min**, server max cap **24 h** regardless of requested duration.
- Optional per-user limit on concurrent active web sessions.

---

## 8. Web Client

- **Origin & CSP:** served **same-origin as the API** (`vault.klyt.eu`) as a
  first-party SPA with a strict CSP (reuse the desktop app's CSP), Subresource
  Integrity on the WASM/JS bundle, no third-party scripts. Same-origin keeps
  `connect-src` to `'self'`, avoids CORS, and means the SPA and API share the one
  Cloudflare-Tunnel-fronted hostname.
- **WASM bridge:** a new `vela-wasm-bridge` crate (sibling to `vela-apple-bridge`
  / `vela-android-bridge`) using `wasm-bindgen`, exposing: ephemeral keypair gen,
  `open_share` (decapsulate capsule), vault chunk decrypt/encrypt, TOTP, password
  strength. Same Rust core, new ABI target `wasm32-unknown-unknown`.
- **UI:** can reuse the desktop Tauri React/TS frontend, gated to read-only in RO
  mode.
- **Memory hygiene:**
  - Vault chunk keys, session tokens, snapshots, and ephemeral keys remain in
    tab/process memory; they are never persisted to `localStorage`, IndexedDB,
    cookies, or `sessionStorage`.
  - Wipe and reload on **`visibilitychange`→hidden** and wipe on
    **`beforeunload`**. Server-side expiry bounds every RW token.
  - A persistent **security-downgrade banner** in RW mode (consistent with the
    SPEC §7.4 WASM-fallback warning), naming the active mode and time remaining.

### 8.1 RW reload behavior (implemented)

A reload ends an RW session. The implemented client deliberately removed the
planned Argon2id/PIN `sessionStorage` resume blob: even wrapped session material
is persistence on the borrowed/shared machines this feature targets. The page
keeps its per-chunk keys, ephemeral signing key, token, and decrypted items only
in memory, clears the old storage key defensively, and requires a fresh approval
after navigation, close, or backgrounding.

---

## 9. Revocation, Audit Logging & RMS Rotation (important)

### 9.1 Revocation semantics

- **RO mode:** because delivery is one-shot (§5.2), there is no server-side
  snapshot to revoke after it has been fetched — and nothing live to cut, since the
  browser only ever held a **point-in-time decrypted copy** (no RMS, no sync).
  Revoking a *pending* (not-yet-fetched) session voids it before delivery. This is
  the recommended, lowest-footprint mode for untrusted devices.
- **RW mode:** revoking stops *future* server sync immediately. **But** a malicious
  browser that received the chunk keys could have copied them, and those keys do
  not rotate; revocation cannot retroact. The honest framing: **revocation + short
  TTL bound exposure; they do not guarantee secrecy of leaked vault keys.** What
  the browser can never leak is the RMS itself — it is not sent (§5.3) — so the
  blast radius stops at vault chunks and never reaches identity, share, audit or
  recovery material.
- **True containment** for a suspected-compromised RW session requires **vault
  re-keying**: rotate the RMS, re-encrypt the vault, re-distribute to all
  permanent devices, and invalidate the old recovery shares. This is a heavy,
  separate feature (a "panic / rotate keys" action) and is **out of scope for v1**,
  but this design's clean separation of ephemeral sessions makes it a natural
  follow-up. Until then, **RO is the default offered for unfamiliar devices.**

### 9.2 Audit logging (in v1)

Web-session lifecycle events are recorded in the **end-to-end encrypted device
audit log** ([SPEC.md §4.4]) — included in v1, not deferred. New event types:

| Event | Logged by | Fields (no plaintext vault data) |
| :--- | :--- | :--- |
| `web_session_granted` | the **approving device** | `session_id`, `mode` (ro/rw), `expires_at`, `reload_survival` (bool), `approver_device_id`, timestamp |
| `web_session_revoked` | the **revoking device** | `session_id`, `revoker_device_id`, timestamp |
| `web_session_expired` | next device to sync after `expires_at` | `session_id`, timestamp |

Entries are appended **only by trusted (enrolled) devices** — never by the web
client itself, even in RW mode — so audit-log integrity stays bound to devices that
hold the RMS via a hardware enclave. The approver writes `web_session_granted` at
grant time; any device writes `web_session_revoked` when it revokes; expiry is
reconciled by the next syncing device (the server's cleanup job removes the session,
and the client notes it). The log remains an opaque XChaCha20-Poly1305 blob under
`audit_key`; the server learns nothing from it.

---

## 10. UX Sketch

1. On the web page: "Access my vault temporarily" → shows a QR + a short numeric
   code, and a spinner ("waiting for approval on your phone…").
2. On the phone: a scan/notification → a confirmation sheet:
   - **Mode:** Read-only by default. Read & write is hidden behind an
     **"Advanced — I trust this device"** toggle (see §9).
   - **Duration:** default **30 min**; presets [30 min] [1 h] [8 h] [24 h] (capped at 24 h).
   - "Approve web access" / "Deny".
3. Web unlocks; a banner shows **mode + countdown** and a **"End session now"**
   button (also endable from the phone or any device under
   *Settings → Devices → Temporary web sessions*).

---

## 11. Future Extensions

- **Scoped RO:** seal only a chosen folder/tag/single item instead of the whole
  vault — minimal-exposure "share one password to a browser for 10 minutes".
- **WebAuthn web login:** allow starting an RW/RO session by passkey assertion
  without another device present.
- **RMS rotation / panic button** (see §9.1).

> Web-session audit logging is **in v1** (§9.2), not a future item.

---

## 12. Implementation Phases

1. **Done — `vela-wasm-bridge`:** keypair generation, `open_share`, chunk crypto,
   signing, and password wrapping primitives used by the browser client.
2. **Done — server:** `web_sessions` table, endpoints, TTL default/cap + cleanup
   job, `web_ephemeral` device kind, token-exp capping.
3. **Done — approver UI** (phone/desktop): scan → confirm mode/duration → seal → grant,
   and **write `web_session_granted` to the audit log** (§9.2). RO snapshot sealing
   plus RW per-chunk-key sealing.
4. **Done — web SPA:** handshake, decapsulation, RO rendering, RW sync/edit,
   memory-only cleanup, and mode/expiry banners.
5. **Done — revocation + audit surfacing** under *Devices → Temporary web sessions*
   (writing `web_session_revoked`/reconciling `web_session_expired`, §9.2) plus
   rate limits, CSP, and lock-on-background hardening.

---

## 13. Resolved Decisions

The initial open questions are resolved (see the summary table in §3):

- **RO snapshot delivery:** ✅ **inline-in-grant, one-shot** — no re-fetchable
  server copy; reload ends the RO session. (§5.2)
- **TTLs & default mode:** ✅ default **RO**, default TTL **30 min**, server max
  **24 h**. (§3, §7)
- **RW exposure:** ✅ RW is **not** offered by default — hidden behind an
  **"Advanced — I trust this device"** toggle given the §9 residual risk. (§9, §10)
- **SPA hosting:** ✅ **same origin as the API** (`vault.klyt.eu`), behind the same
  Cloudflare Tunnel, keeping `connect-src 'self'` and avoiding CORS. (§8)

- **RW reload survival:** ✅ resolved as **no persistence** — reload/background
  ends the session and requires a fresh trusted-device approval. (§8.1)
- **Audit logging:** ✅ **in v1** — web-session grant/revoke/expire events written
  to the encrypted device audit log by trusted devices only. (§9.2)

The v1 design is implemented. Future extensions remain in §11.

---

## 14. Wire formats (v1) — implemented

Defined while building the approver (phase 3) so the web SPA (phase 4) and every
approver platform agree.

### 14.1 Link code / QR payload

The QR (and the pasteable code) is the compact text form — the ~2 KB public key
stays on the server so the code remains scannable:

```text
{session_id}#{fingerprint}#{link_nonce}
```

- `fingerprint` — `base32(sha256(ephemeral_pk)[0..8])`, 13 chars. The approver
  fetches `ephemeral_pk` from `/web-session/{id}/keys` and **must** check it
  against this, which is what detects a server-substituted key.
- `link_nonce` — base32/base64 of the 32 B nonce registered at `start`, echoed
  back in the grant.

All three segments are **required**: the approver apps reject a code that is
missing the fingerprint or the nonce (older short forms and the older
`{"session_id": …}` JSON blob) rather than silently skipping the check.

The account the session is bound to (`approver_user_id`) is **not** in the code —
the user enters it in the browser before the code is generated (§5.1).

### 14.2 Sealed capsule envelope

The approver seals this JSON (UTF-8) to `ephemeral_pk` via the hybrid KEM
(`seal_share`); the browser recovers it with `open_share`:

```json
{ "v": 1, "mode": "ro", "vault": { /* VaultStore */ } }    // read-only snapshot
{ "v": 2, "mode": "rw",                                     // read-write live
  "chunk_keys": { "vault-data-000000": "<base64 32 B>", … } }
```

**The `rw` envelope never carries the RMS.** It carries the per-chunk vault keys
(`kdf::web_session_chunk_keys`: `vault-main`, `vault`, and the first
`WEB_SESSION_DATA_CHUNKS` = 32 `vault-data-NNNNNN` chunks — ~32 MiB of vault
JSON). The browser can read and rewrite the vault for the session, but nothing
else in the key hierarchy — identity, share, audit, MAC, ORAM, recovery — is
reachable from what it holds, and neither is any chunk outside that window
(a vault that outgrows it must be reopened from an app). Clients still on the v1
`rms_b64` envelope are refused by the web client with an "update your app"
message rather than accepted.

Wrapping binary keys as base64 text keeps the sealed plaintext valid UTF-8,
which the JSON-string `open_share` API requires. The `grant` body is then
`{ mode, capsule: base64(sealed_bytes), ttl_secs, link_nonce }`.

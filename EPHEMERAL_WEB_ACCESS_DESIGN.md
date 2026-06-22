# VELA Ephemeral Web Access — Design Document

**Status:** Draft for review
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
  - **RW — Read-Write Live Session:** full vault, edits + sync, RMS in memory only.
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
| What the browser receives | A **decrypted vault snapshot**, sealed by the approver | The **RMS**, sealed by the approver |
| RMS ever in the browser? | **Never** | Yes (process memory only) |
| Live sync / editing | No (point-in-time snapshot) | Yes (full ORAM sync) |
| Server token | Short-lived, read-scoped (snapshot fetch only) | TTL-capped PASETO v4, vault read/write |
| Best for | Untrusted / borrowed device, "just read a password" | Temporary but trusted device |
| Residual risk on revoke | None beyond the snapshot already shown | RMS could have been copied (see §9) |

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
| RW reload survival | **Yes (opt-in per grant):** RMS PIN-wrapped with Argon2id + XChaCha20-Poly1305 in `sessionStorage`, re-validated on reload (§8.1). |
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
  1. POST /web-session/start ──────►│  create pending session     │
       │◄──────── { session_id } ───┤  (status=pending)           │
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
       │◄──── { granted, capsule } ─┤                             │
       │                            │                             │
  8. decapsulate in WASM            │                             │
```

- The **QR channel is never routed through the server** (same property as
  enrollment). The `link_nonce` binds the QR the approver scanned to the session.
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
1. **Seals the RMS** to `ephemeral_pk` via Hybrid KEM (exactly the enrollment
   capsule of [SPEC.md §4.2]).
2. Registers the web session's **hybrid verification key** as an **ephemeral
   device** (`kind = web_ephemeral`, `expires_at`), signing the payload with its
   own identity key, so the web client can authenticate like any device — but with
   a capped lifetime.
3. `POST /web-session/{id}/grant { mode: "rw", capsule, expires_at, web_verification_key, enroll_signature }`.

At step 7–8 the web client:
1. Decapsulates the **RMS into WASM memory only** (never IndexedDB / no keychain).
2. Authenticates as the ephemeral device via `/auth/challenge` + `/auth/verify`,
   receiving a **PASETO whose `exp` is capped to `min(normal_ttl, session.expires_at)`**.
3. Performs normal ORAM vault sync; edits write back through the usual chunk PUTs.

---

## 6. Cryptography

Everything reuses primitives already in `vela-crypto`:

- **Sealing** (`seal_share` / `open_share`, Hybrid ML-KEM-1024 + X25519): used for
  the RW RMS capsule and the RO snapshot capsule. Wire format is the existing
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
    capsule:          Option<Vec<u8>>, // RO snapshot OR RW RMS capsule, sealed
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
| `/web-session/start` | POST | None | Create a pending session; body carries `ephemeral_pk`, `link_nonce`. Returns `session_id`. Rate-limited per IP. |
| `/web-session/{id}` | GET | None (pending) / PASETO (approver) | Web polls for grant status + capsule; approver fetches the pending request to display. |
| `/web-session/{id}/grant` | POST | PASETO v4 (approver) | Body: `mode`, `capsule`, `expires_at`, and (RW) `web_verification_key` + `enroll_signature`. `expires_at` defaults to **30 min** and is capped to the server max of **24 h**. |
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
  - By default, RMS / snapshot / ephemeral keys live in **WASM memory only**;
    never `localStorage`/`IndexedDB`/cookies. The only exception is the opt-in RW
    reload-survival blob below, which is **PIN-wrapped** and in `sessionStorage`.
  - Zeroize and drop on **`visibilitychange`→hidden idle timeout**, on
    **`beforeunload`** (RO; and RW when reload-survival is off), and on **expiry**.
  - An **idle timeout** shorter than the TTL (e.g. 5 min) auto-locks the session.
  - A persistent **security-downgrade banner** in RW mode (consistent with the
    SPEC §7.4 WASM-fallback warning), naming the active mode and time remaining.

### 8.1 RW reload survival within the TTL (Argon2id-wrapped)

By default a page reload ends an RW session (memory-only). Optionally — chosen at
grant time — an RW session can **survive reloads within its TTL** without re-linking
from the phone, using the exact hardening already specified for the browser fallback
in [SPEC.md §7.4]:

1. On RW unlock the web client asks the user to set a **session PIN** (≥ 8 chars,
   per SPEC §7.4 — distinct from any vault password).
2. The PIN is stretched with **Argon2id (3 iterations, 64 MB, 4 parallelism)** to a
   256-bit wrapping key.
3. The **RMS + ephemeral signing key + `session_id` + `expires_at`** are encrypted
   with **XChaCha20-Poly1305** under that key and written to **`sessionStorage`**
   (per-tab; cleared automatically on tab/window close — *not* `localStorage`/
   `IndexedDB`, so it does not persist across a browser restart).
4. **On reload:** prompt for the PIN → Argon2id-unwrap → **re-validate with the
   server** (`GET /web-session/{id}` must return `status = granted` and not expired)
   → resume. If revoked/expired, **wipe** the blob and refuse. A small cap on failed
   PIN attempts (e.g. 5) wipes the blob.

Security properties: Argon2id makes an offline PIN guess expensive should the
`sessionStorage` blob ever spill to disk; the server-side TTL + revocation re-check
on every reload means a revoked session cannot be resumed even with the correct PIN;
and the blob is gone on tab close regardless. This is strictly an RW affordance — RO
never persists anything (§5.2). The security-downgrade banner notes when
reload-survival is active.

---

## 9. Revocation, Audit Logging & RMS Rotation (important)

### 9.1 Revocation semantics

- **RO mode:** because delivery is one-shot (§5.2), there is no server-side
  snapshot to revoke after it has been fetched — and nothing live to cut, since the
  browser only ever held a **point-in-time decrypted copy** (no RMS, no sync).
  Revoking a *pending* (not-yet-fetched) session voids it before delivery. This is
  the recommended, lowest-footprint mode for untrusted devices.
- **RW mode:** revoking stops *future* server sync immediately. **But** a malicious
  browser that received the RMS could have copied it; revocation cannot retroact.
  The honest framing: **revocation + short TTL bound exposure; they do not
  guarantee secrecy of a leaked RMS.**
- **True containment** for a suspected-compromised RW session requires **RMS
  rotation**: generate a new RMS, re-encrypt the vault, re-distribute to all
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

1. **`vela-wasm-bridge`** crate: keypair gen, `open_share`, chunk crypto, TOTP,
   plus **Argon2id wrap/unwrap** (for §8.1) → prove the core runs in-browser. (No UI.)
2. **Server:** `web_sessions` table, the four endpoints, TTL default/cap + cleanup
   job, `web_ephemeral` device kind, token-exp capping.
3. **Approver UI** (phone/desktop): scan → confirm mode/duration → seal → grant,
   and **write `web_session_granted` to the audit log** (§9.2). RO snapshot sealing
   first (lower risk), then RW RMS sealing.
4. **Web SPA:** handshake + decapsulation + read-only render (RO), then RW sync +
   edit, **opt-in Argon2id reload-survival** (§8.1), memory hygiene, banners.
5. **Revocation + audit surfacing** under *Devices → Temporary web sessions*
   (writing `web_session_revoked`/reconciling `web_session_expired`, §9.2) +
   hardening (rate limits, CSP/SRI, idle timeout).

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

- **RW reload survival:** ✅ **yes** — opt-in per grant, RMS PIN-wrapped with
  **Argon2id (3/64 MB/4)** + XChaCha20-Poly1305 in `sessionStorage`, re-validated
  with the server on every reload. (§8.1)
- **Audit logging:** ✅ **in v1** — web-session grant/revoke/expire events written
  to the encrypted device audit log by trusted devices only. (§9.2)

Nothing remains open; the design is ready to implement.

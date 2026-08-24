# Vault Re-keying Design — RMS rotation ("rotate keys")

Status: **crypto, server, and desktop orchestration shipped**; the remaining
platform follow-ups are tracked in §10.

Companion to `EPHEMERAL_WEB_ACCESS_DESIGN.md` §9 (which deferred this feature),
`SECURITY_AUDIT.md` S-1/D-2 residual, and `SPEC.md`.

---

## 1. Problem

Revocation stops *future* server access, but any long-lived key material an
RW web session (or a leaked RMS, or a copied server-side blob) already holds
keeps working forever:

| Leaked today | Survives revocation? |
|---|---|
| RW web-session chunk keys | yes — chunk keys do not rotate |
| Server-side ciphertext copies | yes — keys do not rotate |
| Cloud backup Shamir shares | yes — they reconstruct the RMS |
| The RMS itself | yes — unrecoverable-from, forever |

Rotation retires **all of the above simultaneously**, because every VELA key
derives from the 32-byte RMS by BLAKE3 domain separation
(`vela-crypto/src/kdf.rs`). One seed change moves every derived key at once.

## 2. Invariants (non-negotiable)

1. **The server stays blind.** It never sees `RMS₁`, `RMS₂`, or any derived
   key. Rotation traffic is opaque ciphertext plus KEM-sealed capsules the
   server relays but cannot open — the same capsule mechanism enrollment v3
   shipped (audit P-1).
2. **No privileged device.** Any enrolled device with an unlocked session may
   run rotation. Other devices are passive recipients. The protocol treats
   initiator and adopters identically afterwards.
3. **A write lands in the epoch it was encrypted for, or not at all.**
   Enforced two ways, defense in depth: the server rejects uploads whose
   declared epoch does not match its accepted-write state (§5), and every
   re-keyed chunk carries the epoch inside its AEAD associated data
   (`rekey::epoch_aad`), so a mis-placed blob fails to open instead of
   decrypting into something the caller then trusts (C-2 discipline carried
   forward).
4. **Detect, never trust.** Any epoch ambiguity degrades to an error a client
   can act on (re-fetch, re-push, adopt-and-retry), never to silent corruption.
   On desktop, `key_epoch.enc` is the sole local epoch authority and is
   authenticated by the currently unlocked RMS. An authentication, decryption,
   I/O, or parse failure is fatal before manifest fetch, repair upload, web
   grant, recovery delivery, or rotation start. Independently, a server chunk
   that fails authenticated decryption stops sync without a repair upload.
   Only an absent marker is a supported legacy state, and it means epoch 1
   exactly; plaintext
   `sync_meta.json` contributes chunk clocks but never epoch authority.
   Rekey capsules likewise carry a versioned `{epoch, rotation_id, rms}`
   plaintext authenticated under an RMSₙ-derived transition key, then KEM-sealed
   per device. Adoption verifies that continuity and both inner metadata fields
   before exposing RMSₙ₊₁, so a relay cannot forge, replay, or relabel a seed.

## 3. What rotation covers — and what it does not

Covered (all RMS-derived):

- vault chunks and the aggregate vault blob (`VAULT_ENCRYPTION`, `CHUNK_KEY`),
- audit log key (`AUDIT_LOG`), MAC key, ORAM position-map key,
- share encryption key, identity-keys-at-rest sealing,
- cloud recovery shares (old shares die *by construction*: they reconstruct
  only `RMS₁`; fresh shares of `RMS₂` overwrite the backup),
- RW web-session grants outstanding at rotation time (their chunk keys stop
  decrypting anything).

Explicitly NOT covered:

- **Device identity signing keys** (`hybrid_vk`). They are long-lived but they
  are not vault content; rotating them means re-enrolling every device and
  re-binding WebAuthn credentials — a separate protocol, out of scope here.
  A stolen *device* is handled by `/device/revoke` as today.
- **Retroactive exposure.** An attacker who captured pre-rotation ciphertexts
  AND holds `RMS₁` keeps reading them after rotation. Rotation bounds future
  damage instantly; it cannot un-leak. Same honest framing as §9.1 of the
  ephemeral-web design.

## 4. Key epoch

Each account carries a monotonic **key epoch**: `u64`, starting at `1`,
bumped exactly once per completed rotation. Stored on the `users` row,
served by `GET /vault/epoch`, enforced on chunk writes via the
`X-Vela-Epoch` request header.

Chunks additionally carry their own `epoch` column — the server-side copy of
what the AEAD already binds cryptographically — so the server can serve and
clean up by epoch without decrypting anything.

Device enrollment v2 and v3 carry the authenticated local epoch of the RMS
being sealed. The approving desktop validates it against `GET /vault/epoch`
before reading the RMS, and the server repeats `key_epoch = ? AND
rekey_state IS NULL` atomically with insertion. A stale or mid-rotation
approver therefore cannot create an active device carrying a retired RMS.

## 5. State machine & endpoints

```
                    start                commit
  ACTIVE(N) ───────────────▶ FREEZING(N+1) ───────▶ ACTIVE(N+1)
      ▲                          │                     (shadow rows at
      │      abort / timeout     │                      epoch N deleted;
      └──────────────────────────┘                      capsules stored)
```

All endpoints require device authentication unless noted.

| Endpoint | Effect |
|---|---|
| `GET /vault/epoch` *(device auth)* | `{epoch, state}` — the adoption probe |
| `POST /vault/rekey/start` | `ACTIVE(N) → FREEZING(N+1)`. Returns `{epoch: N+1, rotation_id, chunks: [...]}` — the inventory and unique attempt nonce. Rejects if already `FREEZING`. |
| `POST /vault/rekey/capsules` | Only while `FREEZING`, only from the device that started it, with matching `X-Vela-Rekey-Id`. Body: `{capsules: {device_id: b64}}` — versioned `{epoch, rotation_id, RMS₂}` payloads authenticated with an RMS₁-derived transition key, then sealed to each device's `hybrid_ek`. Stored into `devices.rms_capsule` (the existing read-and-clear relay). |
| `POST /vault/rekey/commit` | Only while `FREEZING`, same device and matching `X-Vela-Rekey-Id`. Atomically validate completeness, set `users.key_epoch = N+1`, and clear state; then best-effort delete chunk rows with `epoch < N+1`. Unfreezes writes. A replay after a lost commit response carries the target epoch in `X-Vela-Epoch` and is answered with success when the account already sits at that epoch — so crash recovery never has to guess between "committed" and "failed". |
| `POST /vault/rekey/abort` | Only while `FREEZING`, same device and matching `X-Vela-Rekey-Id`. Delete rows and capsules for the attempt, back to `ACTIVE(N)`. |
| `PUT /recovery/share` | Body carries the RMS source `key_epoch`; an atomic `key_epoch = ? AND rekey_state IS NULL` update refuses stale or mid-rotation recovery material. `DELETE /recovery/share` has the same guard via `X-Vela-Epoch`. |
| *(automatic)* | A `FREEZING` account older than `REKEY_TIMEOUT` (15 min) rolls back lazily: the next state-observing call for that account performs the abort. No cron. |

Starting the next rotation also requires every active device to have
acknowledged its current-epoch capsule. This preserves the authenticated
RMSₙ→RMSₙ₊₁ chain instead of overwriting the only transition held for an
offline device. Capsule acknowledgement is idempotent, and equal-epoch sync
retries it after a lost response.

Known, accepted limitation: because every successful shadow write refreshes
`rekey_started_at`, an initiator can hold its own account in `FREEZING`
indefinitely by trickling uploads slower than the timeout. This is
account-holder-only authority (the starter check gates shadow writes) and
self-heals on abort or process exit, so it is a self-denial-of-service note,
not an attack vector.

### Write rules (`PUT /vault/chunk/:id`, `oram` writes)

- Header `X-Vela-Epoch` declares the epoch the ciphertext was sealed under.
- Shadow writes additionally carry `X-Vela-Rekey-Id`; this prevents delayed
  traffic from an aborted attempt being accepted by a later attempt targeting
  the same epoch. ORAM's JSON transport carries the epoch in its request body.
- `ACTIVE(N)`: accepts only `N`. A stale declaration gets **409
  `vault_rekeyed`** — the signal devices use to trigger adoption (§7.2).
  A missing header is treated as epoch 1 only while `N == 1`, for legacy
  clients that predate epoch tagging. It is rejected with `vault_rekeyed`
  during `FREEZING` and at every later epoch.
- `FREEZING(N+1)`: accepts only `N+1` — those are the initiator's re-keyed
  copies landing in shadow rows. Everything else is rejected.
- A `web_session` token also carries the epoch at which its chunk-key capsule
  was granted. Request extraction rejects a stale token normally, and chunk
  create/update/delete plus ORAM writes re-check that immutable claim against
  the resolved write epoch in the SQL mutation predicate. A request extracted
  just before commit therefore cannot mutate epoch N+1 with epoch-N keys.
- Epoch 1 keeps the historical chunk-id + Lamport AAD on every bridge,
  including WASM. Epoch-aware chunk AAD is emitted and required only above 1,
  preserving rolling compatibility with clients which predate rotation.

### Shadow rows, not in-place rewrites

Re-keyed chunks are written as NEW rows (`epoch = N+1`) alongside the old ones
until commit. This costs temporary physical storage (bounded by vault size),
but quota is evaluated against the post-commit replacement epoch rather than
double-charging both copies. It buys
the two properties that make crash safety boring:

- **Commit is one atomic compare-and-swap** (validate completeness and flip the
  served epoch together), followed by best-effort cleanup of old rows. Reads
  filter by the served epoch, so cleanup can be retried without exposing a
  mixed state.
- **Abort/timeout is trivially safe** — drop the shadows, nothing else changed.
  A crashed initiator leaves the account exactly as it was.

The unique index moves from `(user_id, chunk_id)` to
`(user_id, chunk_id, epoch)` accordingly.

## 6. Initiator flow (the device where "Rotate keys" was pressed)

Preconditions: unlocked session, full vault locally (or fetched first).

1. Authenticate the local epoch marker, then `GET /vault/epoch` — refuse if
   already `FREEZING` (another rotation in flight; retry later) or if the
   authenticated local epoch differs from the server epoch.
   Before starting, a client attests `/device/rekey-capable` only after it has
   loaded the private half matching its registered `hybrid_ek`. The server
   refuses rotation while any active device has not attested, preventing
   pre-v3 or adoption-unaware clients from being stranded.
2. `POST /vault/rekey/start` → `N+1`, inventory.
3. Generate `RMS₂ ← rekey::rotate()`.
4. Re-encrypt the inventory chunk-by-chunk: download, open under the
   `CHUNK_KEY(RMS₁)` derivation (legacy shapes fall through
   `open_epoch_chunk`'s fallback), re-seal with `seal_epoch_chunk(.., N+1, ..)`,
   upload with `X-Vela-Epoch: N+1`. Sequential, bounded memory; resumable by
   simply restarting (server-side shadows make replays idempotent upserts).
5. Capsule fan-out: `GET /devices`,
   `seal_rekey_capsule(hybrid_ekᵢ, RMS₂, N+1, rotation_id)` for every
   non-revoked device including itself, `POST /vault/rekey/capsules`.
6. `POST /vault/rekey/commit` **while the initiator still holds RMS₁
   locally**. A crash before this call leaves both sides at N and timeout aborts
   the shadows. A crash after it leaves the server at N+1 and the retryable
   self-capsule lets normal sync adopt.
7. Local store migration: `rekey_blob` across `vault.enc`, `audit.enc`,
   `identity_keys.enc`, `shares.enc` (write-temp-rename semantics, same as
   every store save). Re-wrap both the OS-backed RMS and any independent
   master-password RMS, persist the local epoch, then swap the in-memory
   `Crypto` context. Only then acknowledge/clear the self-capsule.
8. Recovery-share rotation: `rekey_recovery_shares(RMS₂, t, n)`, verify with
   `shares_reconstruct_to(.., RMS₂)`, and cache the split with its authenticated
   epoch. Cloud, security-key, and trusted-contact delivery share the sync/rekey
   mutex, probe the server before delivery, and revalidate before recording
   success. Server share writes use an epoch/state compare-and-swap. Cloud
   objects use per-account, per-epoch paths, so a delayed epoch-N upload cannot
   overwrite N+1; recovery also requires the cloud and released server share
   epochs to match. iOS follows the same rule with epoch-specific iCloud KVS
   keys, persists the epoch authenticated by its adopted RMS, and refuses sync,
   web-session grants, or recovery setup when that local epoch differs from the
   active server epoch.
9. Audit event `VaultRekeyed { from_epoch, to_epoch, device_id }` — written
   under the NEW audit key.

## 7. Every other device

### 7.1 Normal case

Next sync: the device probes `GET /vault/epoch` (cheap, cached per sync run),
sees `epoch ≠ own`, then: `GET /device/capsule` (the capsule is sealed to THIS
device's `hybrid_ek`; its authenticated inner epoch and rotation id must match
the committed outer metadata before the RMS is returned), migrates its local store
exactly like step 5 above, durably stores the new RMS and epoch, then
`POST /device/capsule/ack` clears the retryable capsule. Chunks arrive as
ordinary sync data.

### 7.2 Offline-with-new-items (the race that shaped the design)

Device B was offline during rotation and created items locally, encrypted
under `RMS₁`. On reconnect:

1. Epoch probe mismatches → B pushes **nothing** yet. Its queued items stay
   local, perfectly readable — B still holds `RMS₁` until the moment it adopts.
2. B adopts the capsule, migrates its local store (its unsynced items are part
   of that store and come across under `RMS₂` derivations for free).
3. B pushes the items as brand-new creates at epoch `N+1` — accepted, merged,
   nothing lost.

Had B pushed blindly, the server would have stored a chunk nobody can ever
decrypt (every holder of `RMS₁` destroyed it — that destruction IS the
feature). Hence rule §5: stale-epoch writes are refused, not stored.

### 7.3 Mid-rotation stragglers and crashed initiators

- A push that races the snapshot window is refused by the freeze (§5) and
  retried after adoption — the §7.2 path.
- If the initiator crashes between `start` and `commit`, it still holds RMS₁
  locally and timeout rolls the account back to `ACTIVE(N)` cleanly. If it
  crashes after commit but before local migration, its retained self-capsule
  drives the ordinary adoption path on the next sync.
- Belt-and-braces: even if a bug landed an old-epoch blob despite both guards,
  `open_epoch_chunk` refuses it (wrong epoch ≠ legacy), and the authoring
  device still holds the item — re-fetch/re-push recovers.

## 8. Failure-mode summary

| Situation | Outcome |
|---|---|
| Device offline during rotation, gains items | Queued locally; capsule adoption; re-push. **No loss.** |
| Push races the freeze window | Rejected `vault_rekeyed`; retried post-adoption. **No loss.** |
| Guard bug admits an old-epoch blob | Epoch-in-AAD makes it undecryptable-but-detectable; re-fetch from author. **No silent corruption.** |
| Initiator crashes mid-rotation | Resume by any capsule holder, or lazy timeout rollback. Account never left half-migrated. |
| Device lost before adopting | Held nothing unique (pre-rotation data intact server-side); recovers via fresh recovery shares. |
| Attacker holding RMS₁ + pre-rotation capture | Reads what they captured. Out of scope by §3 — containment going forward, not retroactive decryption. |

## 9. Schema changes

```sql
ALTER TABLE users   ADD COLUMN key_epoch        INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users   ADD COLUMN rekey_state      TEXT;                -- NULL | 'freezing'
ALTER TABLE users   ADD COLUMN rekey_started_at TIMESTAMP;
ALTER TABLE users   ADD COLUMN rekey_starter    TEXT;                -- device id
ALTER TABLE users   ADD COLUMN rekey_id         TEXT;                -- attempt UUID

ALTER TABLE vault_chunks ADD COLUMN epoch       INTEGER NOT NULL DEFAULT 1;
ALTER TABLE devices ADD COLUMN rekey_capable INTEGER NOT NULL DEFAULT 0;

DROP INDEX IF EXISTS idx_vault_chunks_user_chunk;
CREATE UNIQUE INDEX idx_vault_chunks_user_chunk_epoch
    ON vault_chunks(user_id, chunk_id, epoch);
-- Serving index for the common read path (current epoch):
CREATE INDEX idx_vault_chunks_user_epoch ON vault_chunks(user_id, epoch);
```

## 10. Rollout status

1. ✅ **Crypto primitive** — `vela-crypto::rekey` (pure, unit-tested; no
   protocol coupling).
2. ✅ **Server** — schema migration + endpoints + epoch write rules + lazy
   rollback; covered by the `rekey_rotation_lifecycle_end_to_end` integration
   test.
3. ✅ **Desktop core** — `commands/rekey::rotate_vault_keys` orchestrating §6,
   restart-safe platform RMS persistence, and the §7.1 adoption hook before any
   sync read/write (settings UI action shipped in gpui; webview port pending).
4. **Follow-ups** — mobile rekey-capsule adoption (Android and iOS can already
   enroll/recover directly into a rotated epoch and perform epoch-bound sync),
   webview rotation UI, and ORAM shadow migration (the server currently refuses
   rotation while an account has ORAM buckets).

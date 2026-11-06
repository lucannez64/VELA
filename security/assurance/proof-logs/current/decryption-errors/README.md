# Uniform decryption errors (plan step C15, the no-error-oracle half of F-4)

Worktree: `/home/hirew/.t3/worktrees/VELA/t3-32edd1fc`
Baseline: `0351452` (fast-forwarded as the step instructs; current `HEAD` before
this work).
Step: C15 — “No error-oracle: all decrypt failures map to one error, proved at
the wrapper.”
F-4 row: `security/assurance/08-formalization-status.md:913` — “verify
application randomness/error/erasure handling”.

## Goal and method

An attacker who supplies ciphertexts must not learn *why* an authenticated open
failed (bad tag, bad length, bad header, bad key, bad capsule, wrong recipient),
because distinguishing causes can turn a decryption routine into an oracle.
This step:

1. inventoried every `open` / `decrypt` / `decapsulate` / verify-and-open entry
   point in `libVELA/vela-crypto/src`;
2. recorded every failure cause each can produce for attacker-controlled input;
3. followed those errors to the boundaries that can expose them (server HTTP
   responses and client code);
4. made every network-ciphertext open wrapper collapse its failures to one
   error and added regression tests that assert the collapse; and
5. classified the remaining, deliberately distinct failures (public headers and
   post-authentication protocol state) and the residual timing risk.

The security model matters here: VELA's storage server is untrusted and never
holds vault/share keys, so **the server is normally the attacker and the client
is the decryptor**. That is why the crypto wrapper, not an HTTP handler, is the
boundary that needs the uniform error.

## Inventory: crypto open paths

`file:line` is the current (post-change) source. “Causes” lists what an attacker
who chooses the bytes can make happen.

| # | Function | Location | Failure causes for attacker input | Error before C15 | Error now |
|---|---|---|---|---|---|
| 1 | `aead::decrypt` | `aead.rs:156` (inner `:160`) | shorter than nonce+tag, wrong key, flipped tag, nonce tamper | `AeadError` for every cause | `DecryptionFailed` |
| 2 | `aead::open` | `aead.rs:104` (inner `:108`) | missing `VAE1` header, short after header, wrong AAD (relabelled chunk/revision), wrong key, bad tag | `AeadError` for every cause | `DecryptionFailed` |
| 3 | `aead::open_vault_chunk` | `aead.rs:55` | sealed vs legacy shape chosen from the public magic; then delegates to 1/2 | `AeadError` | `DecryptionFailed` |
| 4 | `aead::decrypt_with_derived` | `aead.rs:184` | delegates to 1 | `AeadError` | `DecryptionFailed` |
| 5 | `kem::decapsulate` | `kem.rs:160` | low-order X25519 point (`KemError`); wrong ML-KEM ciphertext does not fail (implicit rejection) | `KemError` only | internal; made uniform by 7 |
| 6 | `kem::decapsulate_legacy_v1` | `kem.rs:178` | same as 5, v1 combiner | `KemError` only | internal; made uniform by 7 |
| 7 | `kem::open_share` | `kem.rs:341` (inner `:345`) | short blob, wrong `VKM2` header, malformed capsule, low-order point, wrong key, tampered ML-KEM ciphertext/tag | `InvalidParameter` / `KemError` / `AeadError` | `DecryptionFailed` |
| 8 | `share_envelope::open_signed_item` | `share_envelope.rs:373` | capsule failures (via 7) → uniform; **after** decryption: bad framing, non-UTF-8 field, bad signature, wrong recipient key → `InvalidParameter` | mixed | capsule: `DecryptionFailed`; post-auth: unchanged |
| 9 | `share_envelope::admit` | `share_envelope.rs:425` | policy rejection (replay, wrong pin, wrong sender) → distinct text | `InvalidParameter` | unchanged (policy, not decryption) |
| 10 | `recovery::open_contact_share` | `recovery.rs:292` → `open_for_recipient` `:216` | short, unsupported version, low-order point, wrong recipient, direction confusion, wrong context, bad tag, malformed inner share, wrong coordinate | `InvalidParameter` / `KemError` / `AeadError` / `ShamirError` | `DecryptionFailed` |
| 11 | `recovery::open_contact_share_response` | `recovery.rs:312` → same helper | same as 10 (response domain) | mixed | `DecryptionFailed` |
| 12 | `recovery::reconstruct_account_recovery` | `recovery.rs:70` | policy rejection (cross-account, mixed epoch/split, duplicate channel/coordinate, unbound share) → one message; malformed/tampered share → `shamir::reconstruct` text | `InvalidParameter` / `ShamirError` | unchanged (client-only; MAC check is constant-time) |
| 13 | `recovery::rms_possession_verify_ex` | `recovery.rs:512` | any bad proof → `false`; malformed lengths → `false` | already one `bool` | unchanged |
| 14 | `rekey::open_epoch_chunk` | `rekey.rs:122` | tries current AAD then legacy AAD; both fail → last error | `AeadError` (via 1/2) | `DecryptionFailed` |
| 15 | `rekey::open_fleet_chunk` | `rekey.rs:187` | epoch 0 → `InvalidParameter`; legacy blob after rotation → `InvalidParameter`; otherwise crypto failures via 14 | mixed | crypto: `DecryptionFailed`; protocol state: unchanged |
| 16 | `rekey::open_sealed_fleet_chunk` | `rekey.rs:235` | unsealed pre-C-2 header → `LEGACY_UNSEALED_REFUSAL`; otherwise via 15 | `InvalidParameter` / `AeadError` | header: unchanged (public); crypto: `DecryptionFailed` |
| 17 | `rekey::open_rekey_capsule` | `rekey.rs:330` | wrong device key, tampered capsule, wrong previous RMS → uniform; payload framing/epoch/rotation-id mismatch → `InvalidParameter` **only after** successful authentication under the previous RMS | `KemError` / `InvalidParameter` | crypto: `DecryptionFailed`; post-auth: unchanged |
| 18 | `link::open_link` | `link.rs:80` | wrong link key, wrong passphrase, wrong salt (with passphrase), tampered blob | `AeadError` (via 2) | `DecryptionFailed` |
| 19 | `identity::open` | `identity.rs:312` | wrong sealing key/tamper via 1 → uniform; post-decrypt version/truncation of the **local** file → `InvalidParameter` | mixed | AEAD: `DecryptionFailed`; local parse: unchanged |
| 20 | `identity::open_share` / `open_identity_capsule` | `identity.rs:191`, `:269` | delegate to 7 | mixed | `DecryptionFailed` |
| 21 | `password_kdf::open_with_password` | `password_kdf.rs:147` | local archive/RMS blob: non-magic, unsupported version, implausible Argon2 cost, wrong password, bad tag | `KdfError` / `AeadError` | unchanged (local-file only; see classification) |
| 22 | `shamir::reconstruct` | `shamir.rs:268` | too few shares, y-length mismatch, duplicate x, share failed MAC | `InsufficientShares` / `ShamirError` | unchanged (local; MAC compare constant-time) |
| 23 | `oram::access` | `oram.rs:218` | operates on an already-decrypted path; neither decrypts nor authenticates | — | out of scope |

`open_epoch_chunk` (`rekey.rs:132-138`) is the only place that deliberately runs
two tag checks; its *value* error is still uniform, but see the timing residual.

## Inventory: boundaries that could expose the error

### Server (`serverVELA/vela-server/src`)

The server does **not** hold vault/share keys and never opens attacker-submitted
ciphertext. A full search for `vela_crypto::` gives exactly these uses:

- signature/message construction and verification: `device/enroll.rs:487,503,522,553`,
  `account/mod.rs:153`, `share/mod.rs:934`, `recovery/possess.rs:107`;
- one AEAD decrypt of an **operator-supplied migration bundle with an
  operator-supplied passphrase**: `migration.rs:324`, already mapped to the one
  message “failed to decrypt migration bundle; wrong passphrase or corrupted
  bundle” (`migration.rs:325`).

The endpoints named in the task therefore store, serve or authenticate opaque
bytes; they do not decrypt them:

| Endpoint | Handler | What it does with attacker/client bytes | Oracle risk |
|---|---|---|---|
| `POST /share/send` | `share/mod.rs:338` | base64-decodes the capsule and checks size; stores it. `share_failure_error` (`:75`) reports only shape/size/policy | none (no open) |
| `GET /share/inbox`, `GET /share/linked` | `share/mod.rs:453`, `:621` | returns stored capsules | none (no open) |
| `PUT /share/linked/:id` | `share/mod.rs:695` | re-stores a capsule after decode/size check | none (no open) |
| `POST /send`, `GET /send/:id` | `send.rs:169`, `:370` | stores/serves ciphertext; link decryption happens in the browser with the URL-fragment key (`webVELA/src/send.ts:180-197`). Missing/expired/revoked all return the same `SEND_NOT_FOUND` (`send.rs:52`) | none (no server open) |
| `POST /web-session/:id/grant` | `web_session/mod.rs:837` | base64-decodes and stores the sealed capsule; validates mode/epoch/size only | none (no open) |
| `GET /web-session/:id` | `web_session/mod.rs:443` | serves the capsule once; missing session and wrong poll secret share `401 "web session not found"` (`:422-473`) | none (no open) |
| `POST /recovery/recover/proof` | `recovery/possess.rs:306` | verifies a possession **signature**; `verify_possession_proof` (`:98`) calls the crypto verifier that returns one `bool`. Failure classes are public protocol state (`:362-393`) | not a decryption oracle (see classification) |
| `POST /device/enroll`, `POST /auth/verify` | `device/enroll.rs:475`, `auth/verify.rs` | hybrid signature verification; every `Unauthorized` is rewritten to `DEVICE_AUTH_FAILED` (`enroll.rs:40,47`) | already uniform |
| `PUT /share/my-ek`, `POST /account/register` | `share/mod.rs:1016`, `account/mod.rs:153` | verifies a share-key binding signature; the handler keeps only `signature_verified: bool` (`share/mod.rs:959-968`) and the policy returns one `EkPolicyRejected` message (`:127-129`); the register path uses one `unauthorized_message` | already uniform at the crypto layer |
| `GET/PUT/DELETE /recovery/share` | `recovery/mod.rs` | stores/serves shares; no open | none (no open) |

### Client paths that could report back

No VELA client sends a decryption error back to the server. Searches for an
error-report/telemetry/crash-upload endpoint found none; the relevant client
paths only surface the error locally:

- wasm bridge: `open_share_impl` / `open_link_impl` / `decrypt_admitted_vault_chunk_impl`
  (`libVELA/vela-wasm-bridge/src/lib.rs:259,276,339`) turn a `VelaError` into a
  JSON `error` string; the SPA throws it to local UI (`webVELA/src/vela.ts:21-24`),
  and the anonymous send page collapses every decrypt failure to one message
  (“That passphrase did not work.” / “The key in this link does not match…”)
  (`webVELA/src/send.ts:180-197`).
- desktop: chunk open errors become a local `ChunkOutcome::Corrupt`
  (`desktopVELA/vela-desktop-core/src/sync.rs:1115-1144`); share admission
  errors are shown locally (`desktopVELA/vela-desktop-core/src/sharing.rs:376`).
- iOS/Android bridges stringify the same `VelaError` to their local UI; neither
  has a server report path.

## Classification

### Safe by construction or by public input

1. **The AEAD is a single-tag AEAD with no padding.** XChaCha20-Poly1305
   (`aead.rs`) has exactly one authentication check; there is no “bad padding”
   branch to distinguish. Before C15 `open`/`decrypt` already returned one
   `AeadError`; now they return one `DecryptionFailed`.
2. **Pre-tag length and magic checks are harmless.** `open_inner`
   (`aead.rs:109-115`), `decrypt_inner` (`:161-163`), `open_share_inner`
   (`kem.rs:347-354`) and `open_for_recipient_inner` (`recovery.rs:241-257`)
   inspect bytes the attacker supplied (length, `VAE1`/`VKM2`, version byte).
   The attacker already knows them, so naming the cause leaks nothing. The
   wrappers now hide even these.
3. **ML-KEM already fails uniformly.** A wrong ciphertext decapsulates by
   implicit rejection to a pseudorandom secret (`kem.rs:409` test), and the
   AEAD tag rejects it. The only early decapsulation failure is a low-order
   X25519 point (`kem.rs:163-165`), which the attacker chose and can recognise
   locally; `open_share` also collapses it.
4. **Public protocol-state refusals stay distinct deliberately.** The
   unsealed legacy chunk header (`rekey.rs:242-246`, exported as
   `LEGACY_UNSEALED_REFUSAL`), “legacy ciphertext forbidden after epoch 1”
   (`rekey.rs:202-206`), re-key capsule epoch/rotation-id mismatches
   (`rekey.rs:351-393`) and password-blob format errors (`password_kdf.rs:148-178`)
   are properties of a header or of metadata the attacker supplied, and Android/
   iOS branch on the legacy-refusal text to show a migration hint. They reveal
   nothing beyond the input.
5. **Local-file decryption is not a remote boundary.** `password_kdf::
   open_with_password`, `identity::open` (post-AEAD parsing) and
   `shamir::reconstruct` operate on the user's own files/shares or on a local
   recovery ceremony. Their callers already collapse failures to one
   user-facing message (`desktopVELA/vela-desktop-core/src/commands/vault.rs:1368-1371`,
   `biometric.rs:1325`). They were left detailed for local diagnosis.
6. **Server-side signature verification is already uniform where it matters.**
   Device authentication rewrites every `Unauthorized` to `DEVICE_AUTH_FAILED`
   (`device/enroll.rs:40-52`); share-key registration reduces the signature to
   a boolean before the policy decides (`share/mod.rs:959-968`); the possession
   verifier returns one `bool` by construction (`recovery.rs:512-563`).

### Not a decryption oracle, but worth naming

- **`/recovery/recover/proof` distinguishes protocol states** — expired attempt
  (`400`), binding mismatch (`401`), account absent (`404`), no commitment
  (`401`), proof rejected (`401`) (`recovery/possess.rs:362-393`). These are
  states of the *attempt*, not causes of a decryption failure; the proof is a
  signature over a server-issued challenge, and the verifier cannot leak a key
  through a cause. The `404`/commitment distinctions are account-state
  enumeration questions tracked separately, not F-4 decryption errors.
- **Post-authentication share-envelope checks** (`share_envelope.rs:378-417`)
  distinguish framing/signature/recipient errors after a successful AEAD open.
  The plaintext there is attacker-authored (anyone can seal to a published
  `share_ek`), but the error is only shown to the local recipient, who is the
  party being attacked; there is no report path back. This is sender
  authentication, not decryption.

## Fix

### `libVELA/vela-crypto/src/error.rs`

- New variant `VelaError::DecryptionFailed` with the single message
  `"decryption failed"` (`error.rs:11-19`).
- New helper `uniform_open` (`error.rs:42-52`) that maps *any* error to that
  variant. Every network-facing open wrapper is a one-line call to it, so the
  uniformity is structural rather than remembered at each return.

### Open wrappers

- `aead::open` / `aead::decrypt` now wrap their inner implementations
  (`aead.rs:104-105,156-157`); the header/length/tag checks remain in
  `*_inner` but no caller can see which one fired.
- `kem::open_share` wraps `open_share_inner` (`kem.rs:341-359`). This covers
  share capsules, web-session capsules, identity RMS capsules and the outer
  layer of contact envelopes and re-key capsules.
- `recovery::open_for_recipient` wraps `open_for_recipient_inner`
  (`recovery.rs:216-275`), covering both contact delivery and response
  envelopes.
- `rekey::open_rekey_capsule` no longer rewrites the KEM/AEAD errors into
  `KemError` / a specific `InvalidParameter` (`rekey.rs:342-349`); the two
  cryptographic opens propagate the uniform error. The post-authentication
  metadata checks are unchanged.
- `link::open_link` inherits the uniform AEAD error; no source change was
  needed beyond the wrapper it calls.
- `share_envelope::open_signed_item`, `identity::open_share` and
  `open_identity_capsule` inherit the uniform capsule error automatically.

No server code was changed: there is no server-side ciphertext open to fix.
This is deliberate and supported by the inventory above.

## Tests

All heavy commands ran through
`~/.local/opt/vela-tools/bin/vela-heavy` with
`VELA_STEP_TIMEOUT=3600` and
`CARGO_TARGET_DIR=/home/hirew/.t3/worktrees/VELA/t3-32edd1fc/target-vela-c15-errors`.

| Command | Result | Log |
|---|---|---|
| `cargo test --locked` in `libVELA/vela-crypto` | **138 passed, 0 failed** (plus 4 ORAM integration tests and 2 doc-tests) | [`cargo-test.log`](cargo-test.log) |

New regression tests (each asserts the *same* error for every cause, and that
no attacker-chosen blob opens):

- `aead::tests::every_open_failure_is_the_same_error` — too short, no sealed
  header, short sealed blob, wrong key, flipped tag, wrong AAD.
- `kem::tests::every_open_share_failure_is_the_same_error` — empty, exactly
  header length, wrong `VKM2` magic, corrupt ML-KEM ciphertext, low-order
  X25519 ephemeral, flipped tag, wrong secret key.
- `recovery::tests::every_contact_envelope_open_failure_is_the_same_error` —
  short, unsupported version, wrong recipient key, flipped tag, relabelled
  context, delivery-as-response direction confusion, well-formed envelope with
  a non-share inner plaintext.
- `rekey::tests::every_rekey_capsule_cryptographic_failure_is_the_same_error` —
  wrong device key, tampered capsule, wrong previous RMS; and a control that a
  replayed *valid* capsule with the wrong expected epoch stays a
  post-authentication `InvalidParameter`.
- `rekey::tests::fleet_chunk_cryptographic_failures_are_uniform` — tampered
  blob, wrong key, wrong chunk id, wrong revision, at epochs 1–3 through the
  production `open_sealed_fleet_chunk` gate.
- `share_envelope::tests::tampered_capsules_report_the_uniform_decryption_error`
  — tampered, truncated, wrong-header and wrong-recipient capsules.
- `link::tests::every_link_open_failure_is_the_same_error` — wrong link key,
  tampered blob, wrong salt (passphrase link), wrong/missing passphrase.

Existing positive controls still pass: every wrapper opens its own valid output,
AAD relabelling still fails, and the legacy-shape admission refusal keeps its
documented message.

## Residual risks (not addressed by C15)

1. **Timing.** Uniform *values* do not make the code paths equal-time. An
   observer who can time a client or a future remote opener can still see
   early return on a short/headerless blob (`aead.rs:109-115`,
   `kem.rs:347-354`), the difference between one and two tag checks in
   `open_epoch_chunk` (`rekey.rs:132-138`), the cost of ML-KEM decapsulation
   before the AEAD check, and post-open signature verification. The length/
   header cases are public input; the epoch case reveals only an epoch the
   server already supplies. A full fix needs constant-time/dummy-work padding,
   which is outside this step.
2. **Local diagnostics for network ciphertext are now lost.** Callers that want
   to tell a user *why* an attacker-supplied capsule failed must log at the
   point of production before mapping; none currently does, consistent with the
   existing practice of not logging key material. Local-file paths
   (`password_kdf`, `identity`, `shamir`) keep detailed errors.
3. **Signature/proof verification is not covered by the uniform error.** It is
   not decryption, and the server already collapses device-auth failures.
   `/recovery/recover/proof` still distinguishes protocol states and can reveal
   account state to an unauthenticated caller within its rate limits; that is a
   separate enumeration question.
4. **Legacy v1 formats remain.** The 32-byte v1 possession commitment
   (`recovery.rs:503-523`) and the v1 KEM combiner (`decapsulate_legacy_v1`)
   still exist; retiring them is step C17.
5. **No formal machine-checked proof was added.** The “proved at the wrapper”
   property is enforced structurally (one helper) and by the regression tests
   above, not by a new hax/F* contract. That remains unverified.
6. **No remote decryption endpoint exists today.** If one is added (for example
   a server-side migration or debugging API), it must call these wrappers; a
   future reviewer should re-run the inventory rather than assume this file
   still covers it.

## Suggested follow-ups

- Add a timing test or constant-time wrapper if a remote opener is ever
  introduced; at minimum, avoid two sequential tag checks in a path whose
  timing an attacker can sample.
- Consider collapsing the recovery-proof protocol-state responses if account
  enumeration through `/recovery/*` is brought into scope.
- C17: remove or explicitly exclude the legacy v1 combiner and 32-byte
  possession commitment.
- Add the `uniform_open` invariant to the fuzz corpus (`libVELA/vela-core/fuzz`)
  so a future return path cannot reintroduce a distinct error.

# Bridge thinness (N2a, N2b, N2c)

Worktree: `/home/hirew/.t3/worktrees/VELA/t3-a3f2adc2`
Base: `4140136`, plus the previous delegate's saved work `8c280fe`
(cherry-picked; one missing `rekey` import in the Apple bridge fixed).

## What "thin" means here

The maintainer decision in `security/assurance/09-target-contract.md`
("Scope decisions", plan step N4) says security decisions stay in the verified
Rust core and the Kotlin, Swift and TypeScript callers stay thin. For the FFI
boundary this log uses:

- **thin (a)** — the export decodes its request, calls reviewed core/policy
  functions, and encodes the response. It contains no branch that chooses a
  security outcome, no default that changes one, and no check that another
  bridge implements differently. Some exports compose two or three core calls
  (`kdf::derive` then `aead::encrypt`; `rotate_share_key` then `seal`;
  `sign` then `commitment`); those are still conversions: every decision inside
  them is the core's.
- **logic that belongs in the core (b)** — a security decision, a default
  (`epoch.unwrap_or(1)`), a length normalisation (Apple truncated an over-long
  RMS capsule where Android rejected it), or a duplicated check. The N2 work
  moved these into one shared core function where that was a small
  behaviour-preserving change; the one deferred case is called out below.
- **dead (c)** — no production caller in this repository per the FFI inventory
  (`security/assurance/proof-logs/current/ffi-inventory/README.md`, F12).
  These exports are still thin where they have code; they are kept for ABI
  compatibility and their removal/gating is a follow-up.

Class (a) does not mean "exactly one call": it means "no decision of its own".
The CI guard (`security/formal/check-bridge-thinness.py`) enforces that reading
of the N4 decision: it counts decision constructs, defaults, and calls to
anything that is not a reviewed core function, not the number of core calls.

## Shared core moves

| Moved logic | Was | Now | Used by |
|---|---|---|---|
| Production chunk-download admission (epoch match, sealed open, rollback decision, typed refusal) | Inline in each bridge; WASM had its own `AdmissionState` | `vela_crypto::admission::{admit_download, DownloadRequest, DownloadRefusal, AdmittedDownload, DownloadAdmissionState}` (`libVELA/vela-crypto/src/admission.rs`) | Android `nativeDecryptAdmittedVaultChunkJson`, Apple `vela_ffi_decrypt_admitted_vault_chunk_json`, WASM `decrypt_admitted_vault_chunk_json` |
| Absent chunk epoch means epoch 1 | Android rejected an absent field; Apple `#[serde(default = "default_key_epoch")]`; WASM `unwrap_or(1)` | `rekey::{DEFAULT_FLEET_EPOCH, seal_fleet_chunk_optional_epoch, open_fleet_chunk_optional_epoch}` (`libVELA/vela-crypto/src/rekey.rs`) | Android encrypt chunk (passes `Some`), Apple encrypt/decrypt chunk, WASM encrypt chunk |
| RMS transfer capsule must be exactly 32 bytes | Android rejected `!= 32`; Apple accepted `>= 32` and truncated to the first 32 (F11) | `recovery::open_rms_transfer_capsule` (`libVELA/vela-crypto/src/recovery.rs`) | Android `nativeDecryptRmsCapsuleJson`, Apple `vela_ffi_decrypt_rms_capsule_json` |
| Enrollment capsule must open to exactly a 32-byte RMS | Repeated `len() != 32` after `open_identity_capsule` in both bridges | `DeviceIdentity::open_identity_capsule_rms` (`libVELA/vela-crypto/src/identity.rs`) | Android/Apple enrollment-capsule exports |
| Recovery request path selection (bound shares / flat cloud+server / legacy Shamir) and the "exactly two shares" rule | Duplicated in both mobile bridges | `recovery::{CombineShareInput, CombineRecoveryInput, combine_recovery_shares}` | Android `nativeCombineRecoveryJson`, Apple `vela_ffi_combine_recovery_json` |
| Recovery channel wire names | Duplicated `match` in both mobile bridges | `RecoveryShareChannel::from_wire_name` | same two exports |
| Contact-envelope opener choice from the `response` boolean | Apple bridge branch | `recovery::open_contact_share_for_direction` | Apple `vela_ffi_open_contact_share_json` |
| Publication action wire names | Duplicated seven-arm `match` in both mobile bridges | `PublicationAction::as_str` (`libVELA/vela-client-recovery-policy/src/lib.rs`) | Android/Apple publication-plan exports |

Behaviour decisions recorded while consolidating:

1. **Apple RMS capsule is now strict, like Android.** A plaintext longer than
   32 bytes is refused instead of silently truncated. Truncation turned a
   differently shaped payload into a key the caller did not intend, so the
   stricter rule applies to both bridges (F11). The same strict 32-byte rule
   now lives in `open_rms_transfer_capsule`, which both bridges call.
2. **Absent chunk epoch still means 1, but only in the core.** Apple and WASM
   keep their wire behaviour; Android still requires the field in its request
   DTO and passes `Some`, so an absent Android epoch is still a decode error.
   All three now share the same positivity rule and message.
3. **WASM admission order follows the two mobile bridges.** The shared
   pipeline checks epoch agreement first and then opens through
   `rekey::open_sealed_fleet_chunk`, which refuses the pre-C-2 unsealed shape.
   WASM previously checked `aead::is_sealed` before the epoch. When a blob is
   *both* unsealed and epoch-mismatched, WASM now reports the epoch refusal
   instead of the migration hint. Both cases still refuse; a normally-shaped
   unsealed blob (matching epoch) still gets
   `rekey::LEGACY_UNSEALED_REFUSAL`, so the client's F9 substring branch is
   unchanged.
4. **WASM tab state moved into the core.** `DownloadAdmissionState` still pins
   the first admitted epoch and records the admitted revision only after the
   plaintext was produced and decoded, so a failed attempt moves nothing. The
   browser still supplies the thread-local storage.

## Classification tables

Counts: Android 43 exports = 28 (a) + 4 (b, deferred) + 11 (c);
Apple 39 = 29 (a) + 0 (b) + 10 (c);
WASM 9 = 7 (a) + 0 (b) + 2 (c). Total 91 = 64 (a) + 4 (b) + 23 (c).

### Android (`libVELA/vela-android-bridge/src/lib.rs`, 43)

| Export | Class | Reviewed core call(s) | Note |
|---|---|---|---|
| `vela_bridge_version` | c | — | literal; no production caller |
| `vela_bridge_free_string` | c | — | C-ABI free; no production caller |
| `vela_bridge_free_bytes` | c | — | C-ABI free; in-crate tests only |
| `vela_password_strength_json` | c | `calculate_password_strength` | C-ABI test harness only |
| `vela_encrypt_vault_json` | c | `kdf::derive`, `aead::encrypt` | C-ABI test harness only; validates `VaultStore` |
| `vela_decrypt_vault_json` | c | `kdf::derive`, `aead::decrypt` | C-ABI test harness only |
| `vela_encrypt_bytes` | c | `kdf::derive`, `aead::encrypt` | no caller (F12) |
| `nativeVersion` | a | — | literal version string |
| `nativeEnrollmentVerificationCode` | a | `verification::enrollment_verification_code` | JNI decode failure becomes `""` (ABI error mapping) |
| `nativeEncryptVaultJson` | a | `kdf::derive`, `aead::encrypt` | validates `VaultStore` before sealing |
| `nativeDecryptVaultJson` | a | `kdf::derive`, `aead::decrypt` | |
| `nativeEncryptVaultChunkJson` | a | `kdf::chunk_key`, `rekey::seal_fleet_chunk_optional_epoch` | passes `Some(key_epoch)`; positivity in core |
| `nativeDecryptVaultChunkJson` | c | `kdf::chunk_key`, `rekey::open_fleet_chunk` | non-admitting low-level path; only dead `decryptSyncedVault` calls it (F12) |
| `nativeDecryptAdmittedVaultChunkJson` | a | `kdf::chunk_key`, `admission::admit_download` | production download path |
| `nativeIdentityCreateJson` | a | `DeviceIdentity::generate`, `identity::register`, `identity.seal` | |
| `nativeIdentityImportJson` | a | `DeviceIdentity::import`, `identity::register`, `identity.seal` | empty optional key strings decode to `None` |
| `nativeIdentityOpenJson` | a | `DeviceIdentity::open`, `identity::register`, `identity.seal` | |
| `nativeIdentityRotateShareKeyJson` | a | `identity.rotate_share_key`, `identity.seal` | |
| `nativeIdentitySignJson` | a | `identity.sign_auth` | |
| `nativeIdentitySignShareEkJson` | a | `identity.sign_share_ek_binding` | |
| `nativeOpenRekeyCapsuleJson` | c | `rekey::open_rekey_capsule` | no Kotlin `external` (F12) |
| `nativePasskeyKeygenJson` | b | bridge-local `passkey::keygen` | F4: hand-mirrored WebAuthn primitives; move to a shared core crate is a listed follow-up |
| `nativePasskeyAuthDataJson` | b | bridge-local `passkey::build_authenticator_data` | F4/F5: UV bit arrives from Kotlin; deferred |
| `nativePasskeyAttestationObjectJson` | b | bridge-local `passkey::build_attestation_object` | F4; deferred |
| `nativePasskeySignJson` | b | bridge-local `passkey::sign` | F4; deferred |
| `nativeIdentityEnrollmentFingerprintJson` | a | `identity.enrollment_fingerprint` | |
| `nativeIdentitySignEnrollmentResultJson` | a | `identity.sign_enrollment_result` | |
| `nativeIdentityOpenEnrollmentCapsuleJson` | a | `DeviceIdentity::open_identity_capsule_rms` | exact 32-byte rule now in core |
| `nativeIdentitySealSignedShareJson` | a | `identity.seal_signed_share` | |
| `nativeIdentityAdmitShareJson` | a | `identity.admit_share` | admission policy stays in `vela-client-share-policy`; `pin` is optional wire data |
| `nativeIdentityOpenShareJson` | c | `identity.open_share` | Kotlin wrapper has no caller (F12) |
| `nativeIdentityForgetJson` | a | `identity::forget` | |
| `nativeIdentityForgetAllJson` | c | `identity::forget_all` | Kotlin wrapper has no caller (F12) |
| `nativeWebSessionChunkKeysJson` | a | `kdf::web_session_chunk_keys` | |
| `nativeDecryptRmsCapsuleJson` | a | `recovery::open_rms_transfer_capsule` | exact 32-byte rule now shared |
| `nativeDecryptEnrollmentPackageJson` | a | `aead::decrypt` | 32-byte key decode |
| `nativeSealShareJson` | a | `kem::seal_share` | |
| `nativeSplitRecoveryJson` | a | `shamir::split` | |
| `nativeCombineRecoveryJson` | a | `recovery::combine_recovery_shares` | path selection now shared |
| `nativeRmsPossessionHashJson` | a | `recovery::rms_possession_commitment` | 32-byte RMS decode via `raw_rms` |
| `nativePlanRecoveryPublicationJson` | a | `plan_publication_resume`, `PublicationAction::as_str` | wire names now shared |
| `nativeParseImportJson` | a | `vela_import::parse_import_request` | |
| `nativeRichItemsJson` | a | `vela_core::rich_api::process` | |

### Apple (`libVELA/vela-apple-bridge/src/lib.rs`, 39)

| Export | Class | Reviewed core call(s) | Note |
|---|---|---|---|
| `vela_ffi_version` | a | — | literal version string |
| `vela_ffi_free_string` | a | — | C-ABI free |
| `vela_ffi_enrollment_verification_code` | a | `verification::enrollment_verification_code` | null C string becomes `""` |
| `vela_ffi_password_strength_json` | c | `calculate_password_strength` | Swift wrapper has no caller (F12) |
| `vela_ffi_encrypt_vault_json` | a | `kdf::derive`, `aead::encrypt` | validates `VaultStore` |
| `vela_ffi_decrypt_vault_json` | a | `kdf::derive`, `aead::decrypt` | |
| `vela_ffi_identity_create` | a | `DeviceIdentity::generate`, `identity::register`, `identity.seal` | |
| `vela_ffi_identity_import` | a | `DeviceIdentity::import`, `identity::register`, `identity.seal` | empty optional key strings decode to `None` |
| `vela_ffi_identity_open` | a | `DeviceIdentity::open`, `identity::register`, `identity.seal` | |
| `vela_ffi_identity_rotate_share_key` | a | `identity.rotate_share_key`, `identity.seal` | |
| `vela_ffi_open_rekey_capsule_json` | c | `rekey::open_rekey_capsule` | no Swift wrapper (F12) |
| `vela_ffi_identity_sign_share_ek_json` | a | `identity.sign_share_ek_binding` | |
| `vela_ffi_identity_sign_json` | a | `identity.sign_auth` | |
| `vela_ffi_identity_open_share_json` | c | `identity.open_share` | Swift wrapper has no caller (F12) |
| `vela_ffi_identity_seal_signed_share_json` | a | `identity.seal_signed_share` | |
| `vela_ffi_identity_admit_share_json` | a | `identity.admit_share` | admission policy stays in `vela-client-share-policy` |
| `vela_ffi_identity_enrollment_fingerprint_json` | a | `identity.enrollment_fingerprint` | |
| `vela_ffi_identity_sign_enrollment_result_json` | a | `identity.sign_enrollment_result` | |
| `vela_ffi_identity_open_enrollment_capsule_json` | a | `DeviceIdentity::open_identity_capsule_rms` | exact 32-byte rule now in core |
| `vela_ffi_identity_forget_json` | c | `identity::forget` | Swift wrapper has no caller (F12) |
| `vela_ffi_identity_forget_all` | a | `identity::forget_all` | |
| `vela_ffi_web_session_chunk_keys_json` | a | `kdf::web_session_chunk_keys` | |
| `vela_ffi_encrypt_vault_chunk_json` | a | `kdf::chunk_key`, `rekey::seal_fleet_chunk_optional_epoch` | absent epoch -> 1 in core |
| `vela_ffi_decrypt_vault_chunk_json` | c | `kdf::chunk_key`, `rekey::open_fleet_chunk_optional_epoch` | tests only; no production caller (F12) |
| `vela_ffi_decrypt_admitted_vault_chunk_json` | a | `kdf::chunk_key`, `admission::admit_download` | production download path |
| `vela_ffi_decrypt_rms_capsule_json` | a | `recovery::open_rms_transfer_capsule` | stricter than before: exact 32 bytes, no truncation |
| `vela_ffi_decrypt_enrollment_package_json` | a | `aead::decrypt` | 32-byte key decode |
| `vela_ffi_split_recovery_json` | a | `shamir::split` | |
| `vela_ffi_combine_recovery_json` | a | `recovery::combine_recovery_shares` | path selection now shared |
| `vela_ffi_seal_contact_share_json` | c | `recovery::seal_contact_share` | no Swift wrapper (F12) |
| `vela_ffi_open_contact_share_json` | c | `recovery::open_contact_share_for_direction` | no Swift wrapper (F12); opener choice now in core |
| `vela_ffi_seal_contact_share_response_json` | c | `recovery::seal_contact_share_response` | no Swift wrapper (F12) |
| `vela_ffi_possession_proof_json` | c | `recovery::rms_possession_sign`, `recovery::rms_possession_commitment` | no Swift wrapper (F12) |
| `vela_ffi_generate_recovery_request_json` | c | `kem::generate_keypair` | no Swift wrapper (F12) |
| `vela_ffi_rms_possession_hash_json` | a | `recovery::rms_possession_commitment` | 32-byte RMS decode |
| `vela_ffi_plan_recovery_publication_json` | a | `plan_publication_resume`, `PublicationAction::as_str` | wire names now shared |
| `vela_ffi_seal_share_json` | a | `kem::seal_share` | |
| `vela_ffi_rich_items_json` | a | `vela_core::rich_api::process` | |
| `vela_ffi_parse_import_json` | a | `vela_import::parse_import_request` | |

### WASM (`libVELA/vela-wasm-bridge/src/lib.rs`, 9)

| Export | Class | Reviewed core call(s) | Note |
|---|---|---|---|
| `vela_wasm_version` | c | — | literal; not imported by `webVELA/src/vela.ts` (F12) |
| `generate_ephemeral_keypair` | a | `kem::generate_keypair` | |
| `generate_signing_keypair` | a | `signing::generate_keypair` | |
| `create_auth_signature_json` | a | `signing::HybridSigningKey::from_bytes`, `signing::auth_message`, `signing::sign` | |
| `open_share_json` | a | `kem::HybridSecretKey::from_bytes`, `kem::open_share` | |
| `open_link_json` | a | `vela_crypto::link::open_link` | empty passphrase/salt is the wire encoding of absent (allowlisted) |
| `encrypt_vault_chunk_json` | a | `rekey::seal_fleet_chunk_optional_epoch` | absent epoch -> 1 in core |
| `decrypt_admitted_vault_chunk_json` | a | `admission::DownloadAdmissionState::{admit, record}` | production download path; tab state in core |
| `password_strength_json` | c | `calculate_password_strength` | not imported by `webVELA/src/vela.ts` (F12) |

## What the CI guard enforces

`security/formal/check-bridge-thinness.py` (stdlib only, run as
`python3 -I`) parses the three bridge files and resolves every ABI export
(`#[no_mangle]` or `#[wasm_bindgen]`) plus every local helper reachable from
one. It fails when:

- an export is missing from, or new to, the reviewed manifest (91 names);
- a reachable body contains `if`, `match`, `while`, `loop` or `for` outside an
  exact-count, reasoned allowlist entry;
- a reachable body uses `unwrap_or(...)`, `unwrap_or_else(...)` or
  `unwrap_or_default()` outside an exact-count, reasoned entry (a numeric
  argument is also counted by value);
- a body contains a numeric literal outside an exact-count entry (this also
  catches a default written any other way);
- a file has `#[serde(default = "...")]` or a `default_*` helper returning a
  numeric literal;
- a body calls a free function that is neither a reviewed core function, a
  codec/ABI call from the fixed list, nor a reviewed local helper;
- a bridge defines an `impl` block other than `Drop`/`Deref` (method calls are
  otherwise assumed to resolve to std or a core type);
- an allowlist entry is stale (the construct is gone) or has no reason.

Reviewed exceptions are only ABI plumbing and refusal rendering: JNI/C pointer
and string decode, the JSON error envelope, the `unwrap_or*` fallbacks that turn
an allocation or decode failure into a null/empty/error envelope, the
`u64`/`usize` conversions, the 32-byte wire-width checks,
empty-string-means-absent decoding, and the three `*_refusal_message` functions
that turn the core's typed refusal into the client's existing wording. The
Android `passkey::*` module is printed as an explicit exemption (F4), not
silently accepted.

CI runs the guard and its tests in `.github/workflows/security.yml`, directly
after "Check every rendered SQL statement against the schema":

```yaml
- name: Check every bridge export is a thin core call
  run: |
    python3 -I security/formal/check-bridge-thinness.py
    python3 -I -m unittest discover -s security/formal/tests -p 'test_bridge_thinness.py'
```

`security/formal/tests/test_bridge_thinness.py` has nine tests: the real
repository, the 91-export classification, and mutants that add an `if`, add a
numeric default, add a serde default helper, add an `unwrap_or_default`
fallback, call a non-core function, add an unreviewed local helper, and rename
an export. Each mutant must fail with the expected finding.

### What it does not enforce

- **Method calls.** A method call is assumed to resolve to std or a core type.
  The guard does not type-check it. Bridges define no inherent methods; adding
  one is rejected by the `impl` rule.
- **The reviewed core functions themselves.** `admission::admit_download`,
  `combine_recovery_shares`, `open_rms_transfer_capsule`, the `rekey` optional-
  epoch wrappers, `PublicationAction::as_str`, and the hax-verified policies are
  trusted by this guard. Their proofs/tests are the core corpus' job.
- **That an allowlisted decode check is not a security decision.** A reviewer
  must justify each entry's reason. The guard cannot tell a null-pointer check
  from a policy branch.
- **Reachability and callers.** It does not show that production Kotlin, Swift
  or TypeScript uses the admitted export, or that a caller does not pre-check
  or ignore an error. Those are N5-N7. In particular the non-admitting
  `nativeDecryptVaultChunkJson` / `vela_ffi_decrypt_vault_chunk_json` remain
  thin and callable; they are dead in production today (F12) but the guard
  would not stop a future caller.
- **Behaviour preservation.** It checks shape, not semantics. The moves above
  were reviewed by hand and covered by the bridge tests.
- **The Android passkey module.** Four exports call hand-mirrored WebAuthn code
  the guard cannot see into; the exemption is printed on every run (F4).

## Verification

All heavy commands ran through `~/.local/opt/vela-tools/bin/vela-heavy` with
`VELA_STEP_TIMEOUT=3600` and `CARGO_TARGET_DIR=$PWD/target-n2bridges3`, one at
a time. Logs are in this directory.

| Command | Result | Log |
|---|---|---|
| `cargo test --locked` in `libVELA/vela-crypto` | 140 unit + 4 integration + 2 doc tests pass | `cargo-test-crypto.log` |
| `cargo test --locked` in `libVELA/vela-client-recovery-policy` | all tests pass | `cargo-test-recovery-policy.log` |
| `cargo test --locked` in `libVELA/vela-android-bridge` | 28 pass | `cargo-test-android.log` |
| `cargo test --locked` in `libVELA/vela-apple-bridge` | 18 pass | `cargo-test-apple.log` |
| `cargo test --locked` in `libVELA/vela-wasm-bridge` | 16 pass | `cargo-test-wasm.log` |
| `./verify-fstar-sharefacts-tmp.sh` (temporary wrapper around `libVELA/vela-crypto/verify-share-facts-fstar.sh`, deleted before commit) | all verification conditions discharged | `fstar-share-facts.log` |
| `python3 -I security/formal/check-bridge-thinness.py` | exit 0; 43 + 39 + 9 exports thin | — |
| `python3 -I -m unittest discover -s security/formal/tests -p 'test_bridge_thinness.py'` | 9 tests pass | — |

The F* run was required because `libVELA/vela-crypto` changed (new
`admission` module, `recovery`/`rekey`/`identity` additions). Its extraction
selects only `share_envelope`/`signing`/`wire`, so the new module is not in
the F* corpus; the gate confirms the existing verified surface still passes.

## Unverified / follow-ups

- **Passkey primitives (F4/F5).** Four Android exports still call the
  bridge-local `src/passkey.rs`; the guard exempts `passkey::*` and prints the
  exemption. Moving it to a shared core crate and deciding the UV bit in Rust
  remain follow-ups. The four exports are class (b), not (a).
- **Caller-side duplicate decisions (F7).** Kotlin `requireMatchingSyncEpoch`,
  `rejectRollback`, `requireReadableBaseline`, and Swift `SyncEngine` pre-checks
  still exist. They are N5a/N6a work; the bridge pipeline is now the single
  implementation, but the callers can still disagree before calling it.
- **Caller-supplied facts (F8).** `recipient_bound` and the 12
  `plan_publication_resume` facts still arrive from the app. Moving the path
  selection into the core does not authenticate those facts; making the app
  derive or store them is N5c/N6c.
- **Error identity (F9).** The ABI still returns prose, so clients match the
  `LEGACY_UNSEALED_REFUSAL` substring. Machine-readable refusal codes are an
  N3/protocol change.
- **Dead surface (F12).** The 23 class (c) exports are kept for ABI
  compatibility. Removing them, or gating the non-admitting chunk paths behind
  a migration-only API, is a follow-up. `vela_encrypt_bytes` also still has no
  error message on failure.
- **ABI type divergences (F11).** Signature field naming (`signature` vs
  `signature_b64`) and `previous_rms` encoding (JSON integer array vs base64)
  are unchanged; they are N3 type-mapping work, not security decisions.
- **No device/emulator run.** JNI symbol resolution and the Swift XCFramework
  were not executed; the bridge tests are Rust-side only, as in the inventory's
  "What is unverified". The CI guard is source analysis, not a proof.
- **WASM refusal precedence** when a blob is both unsealed and epoch-mismatched
  changed as recorded above. The normal unsealed path and all refusal outcomes
  are unchanged.

# FFI call-site inventory (plan step N1)

Read-only inventory of every place a native or web client enters VELA's Rust core,
so that N2a-c can state what "thin wrapper" means per boundary and N5-N7 can show
that callers reach admission only through those wrappers.

Evidence base: source reading at commit `94696ed` (fast-forwarded from
`t3/external-security-assurance`). **No build, test, JNI or Swift compile was run.**
Machine-readable form: [`ffi-inventory.json`](ffi-inventory.json).

Layout of the boundary:

| Bridge | ABI | Export kind | Consumed by |
|---|---|---|---|
| `libVELA/vela-android-bridge` | JNI + C | 36 `Java_com_vela_android_core_NativeVelaCore_*` + 7 `vela_*` C functions | Kotlin `com.vela.android` (`System.loadLibrary("vela_android_bridge")`, `NativeVelaCore.kt:8`) |
| `libVELA/vela-apple-bridge` | C (`staticlib` -> XCFramework) | 39 `vela_ffi_*` | Swift `iosVELA` via `import VelaCore` (`include/module.modulemap`) |
| `libVELA/vela-wasm-bridge` | `wasm_bindgen` | 9 `#[wasm_bindgen]` functions | TypeScript `webVELA/src/vela.ts` (built by `wasm-pack`, output `webVELA/src/wasm/`, not checked in) |
| `desktopVELA` | **not FFI** — Tauri IPC + in-process | 109 `#[tauri::command]` functions | TS front end (58 `invoke(` calls from 20 files) and the gpui front end (245 `vela_desktop_core::` references) |

`extension/` has **no** path into the Rust core: it calls the desktop's native
messaging host (`extension/src/background/background.js:1725` `sendNativeMessage`),
so it is a caller of desktopVELA, not of a bridge. It performs no chunk crypto.

## Summary counts

| Bridge | Exports | Any call site listed | Reached by reachable production code | No call site at all |
|---|---|---|---|---|
| Android (JNI + C) | 43 | 37 | 32 | 6 |
| Apple (C ABI) | 39 | 33 | 29 | 6 |
| WASM | 9 | 7 | 7 | 2 |
| **Total** | **91** | **77** | **68** | **14** |

"Any call site listed" includes in-crate Rust tests and client wrappers that no
production code calls. "Reached by reachable production code" additionally requires
that the calling client function is itself called somewhere in production, so e.g.
`nativeDecryptVaultChunkJson` counts as unreached even though
`LocalVaultRepository.decryptSyncedVault` calls it. "No call site at all" is listed
in F12.

Per-platform caller counts (production, `grep` counts excluding the wrapper file itself):

| Platform | Call sites into a wrapper | Distinct wrappers used | ABI exports reached | Notes |
|---|---|---|---|---|
| Android (Kotlin) | 50 | 36 | 32 of 43 | `LocalVaultRepository.decryptSyncedVault` is dead |
| iOS (Swift) | 51 | 31 | 29 of 39 | all through `VelaCoreFFI.swift` |
| Web (TypeScript) | 7 | 7 | 7 of 9 | no admission export exists |
| Desktop (Rust, in-process) | 58 `invoke(` + 245 core refs | 109 Tauri commands | n/a | calls `vela-sync-policy` directly (`sync.rs:531`) |

## What each bridge delegates to

Verified policy/core crates and the functions the bridges call:

- `vela-sync-policy` — `plan_sync_epoch_match` (`libVELA/vela-sync-policy/src/lib.rs:198`),
  `plan_chunk_download` (`:281`), `INITIAL_EPOCH` (`:12`). Called only from the two mobile
  bridges; the wasm bridge does not depend on this crate at all.
- `vela-client-recovery-policy` — `plan_publication_resume` (both mobile bridges).
- `vela-client-share-policy` — reached **indirectly** via
  `vela_crypto::share_envelope::admit` (`libVELA/vela-crypto/src/share_envelope.rs:39`,
  `plan_share_admission` used at `:523`, `:532`); neither bridge names it.
- `vela-crypto` — `aead`, `kdf`, `kem`, `rekey`, `shamir`, `identity`, `recovery`,
  `verification`, `signing`, `link` (wasm only).
- `vela-core` — `calculate_password_strength`, `rich_api::process`; `vela-import` —
  `parse_import_request`.

Already proved about the mobile download gates (read for this inventory):
`security/assurance/17-universal-chunk-admission.md` proves the `plan_chunk_download`
kernel over arbitrary facts but states explicitly that it "proves neither that
ciphertext opening established the AAD flag nor that an integer epoch established the
epoch flag"; `security/assurance/18-mobile-sync-admission.md` describes the mobile
routing (integer epoch compare, sealed ciphertext, real open, policy, admitted clock
returned) and records the remaining JNI/C/Swift gaps and the caller-supplied adoption
flag. Both documents assume the path they describe; this inventory shows where callers
take a different path (F1-F3).

## Export tables

### Android (JNI and C ABI) — 43 exports

| Export | Kind | Rust source | Delegates to | Logic beyond conversion | Callers |
|---|---|---|---|---|---|
| `vela_bridge_version` | C | libVELA/vela-android-bridge/src/lib.rs:359 | none — returns the literal "vela-android-bridge/0.1.0" | none | none in production (no caller in repo) |
| `vela_bridge_free_string` | C | libVELA/vela-android-bridge/src/lib.rs:846 | none — drops a CString | none | none in production |
| `vela_bridge_free_bytes` | C | libVELA/vela-android-bridge/src/lib.rs:856 | none — rebuilds a boxed slice and drops it | none | lib.rs:1981 (in-crate test only) |
| `vela_password_strength_json` | C | libVELA/vela-android-bridge/src/lib.rs:865 | vela_core::calculate_password_strength | JSON decode; JSON encode | lib.rs:1987 (in-crate test only) |
| `vela_encrypt_vault_json` | C | libVELA/vela-android-bridge/src/lib.rs:875 | vela_crypto::kdf::derive + aead::encrypt | RMS from base64 in JSON; VaultStore parse validation; base64 out | lib.rs:2432 (in-crate test only) |
| `vela_decrypt_vault_json` | C | libVELA/vela-android-bridge/src/lib.rs:880 | vela_crypto::kdf::derive + aead::decrypt | RMS from base64 in JSON; base64 in; UTF-8 conversion | lib.rs:2446 (in-crate test only) |
| `vela_encrypt_bytes` | C | libVELA/vela-android-bridge/src/lib.rs:885 | vela_crypto::kdf::derive + aead::encrypt | returns VelaByteBuffer; on error returns null/0 with **no error message** | none in production; none in the crate's tests either |
| `nativeVersion` | JNI | libVELA/vela-android-bridge/src/lib.rs:364 | none — literal version string | none | androidVELA/.../core/NativeVelaCore.kt:27 -> SharedCoreStatus.kt:12 (display only) |
| `nativeEnrollmentVerificationCode` | JNI | libVELA/vela-android-bridge/src/lib.rs:376 | vela_crypto::verification::enrollment_verification_code | a JString that fails to decode becomes "" (silently) | androidVELA/.../ui/screens/EnrollDeviceScreen.kt:94 (shows code before import) |
| `nativeEncryptVaultJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:390 | vela_crypto::kdf::derive + aead::encrypt | RMS from JByteArray; VaultStore parse validation; base64 out | androidVELA/.../security/EncryptedVaultStore.kt:84 (persists ciphertext, null -> error) |
| `nativeDecryptVaultJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:403 | vela_crypto::kdf::derive + aead::decrypt | RMS from JByteArray; base64 in; UTF-8 conversion | androidVELA/.../security/EncryptedVaultStore.kt:53 (unlock; null -> error, no fallback) |
| `nativeEncryptVaultChunkJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:416 | vela_crypto::kdf::chunk_key + rekey::seal_fleet_chunk | i64->u64 epoch with positivity check; VaultStore parse validation | androidVELA/.../sync/VaultSyncManager.kt:1061 (upload path); androidVELA/.../core/LocalVaultRepository.kt:102 encryptSnapshotForSync (no live caller) |
| `nativeDecryptVaultChunkJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:429 | vela_crypto::kdf::chunk_key + rekey::open_fleet_chunk | no admission decision of any kind (documented low-level path) | androidVELA/.../core/LocalVaultRepository.kt:116 decryptSyncedVault — dead code: no caller |
| `nativeDecryptAdmittedVaultChunkJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:446 | vela_sync_policy::plan_sync_epoch_match; aead::is_sealed; rekey::open_fleet_chunk; vela_sync_policy::plan_chunk_download | adds: (1) refuses any blob without the VAE1 sealed header — a gate that exists in no policy/crypto crate; (2) sets aad_binding_verified literally true after the open; (3) derives key_epoch_positive from the integer; (4) formats the refusal message; (5) returns the admitted clock | androidVELA/.../sync/VaultSyncManager.kt:988 (downloadRemoteVault; null -> error(); floors recorded only after replaceAllAdmitted 594/678/695/717/748) |
| `nativeIdentityCreateJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:469 | vela_crypto::identity::DeviceIdentity::generate + identity::register | seal key from JByteArray (32-byte check); public halves + sealed blob serialised | androidVELA/.../sync/ServerIdentityStore.kt:68, :108 |
| `nativeIdentityImportJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:482 | vela_crypto::identity::DeviceIdentity::import | base64 decode of hybrid_sk/share_dk/hybrid_ek; empty string means None | androidVELA/.../sync/ServerIdentityStore.kt:151, :257 (legacy migration) |
| `nativeIdentityOpenJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:495 | vela_crypto::identity::DeviceIdentity::open | seal key 32-byte check | androidVELA/.../sync/ServerIdentityStore.kt:177 |
| `nativeIdentityRotateShareKeyJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:508 | identity.rotate_share_key + identity.seal | seal key 32-byte check | androidVELA/.../sync/ServerIdentityStore.kt:190 |
| `nativeIdentitySignJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:521 | identity.sign_auth | base64 decode challenge, base64 encode signature | androidVELA/.../sync/VaultSyncManager.kt:856 (device auth) |
| `nativeIdentitySignShareEkJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:556 | identity.sign_share_ek_binding | base64 decode/encode | androidVELA/.../sync/ServerIdentityStore.kt:74, :114, :194; androidVELA/.../sync/VaultSyncManager.kt:823 |
| `nativeOpenRekeyCapsuleJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:569 | vela_crypto::rekey::open_rekey_capsule | previous_rms arrives as a JSON integer array (key material inside JSON); 32-byte check | none — NativeVelaCore.kt declares no matching external |
| `nativePasskeyKeygenJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:586 | bridge-local src/passkey.rs keygen (p256 + ciborium + sha2). NOT delegated to vela-crypto/vela-core | whole WebAuthn primitive implemented inside the bridge as a hand-mirrored copy of desktopVELA/vela-desktop-core/src/passkey.rs | androidVELA/.../security/passkey/PasskeyAuthenticator.kt:84 |
| `nativePasskeyAuthDataJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:599 | bridge-local passkey::build_authenticator_data | same mirrored implementation; the UP/UV flags arrive as an opaque caller int | androidVELA/.../security/passkey/PasskeyAuthenticator.kt:89, :171 |
| `nativePasskeyAttestationObjectJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:612 | bridge-local passkey::build_attestation_object | same mirrored implementation (none attestation, zero AAGUID) | .../PasskeyAuthenticator.kt:96 |
| `nativePasskeySignJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:625 | bridge-local passkey::sign (p256 ECDSA-SHA256, DER) | same mirrored implementation | .../PasskeyAuthenticator.kt:180 |
| `nativeIdentityEnrollmentFingerprintJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:640 | identity.enrollment_fingerprint | handle only; no key bytes accepted | androidVELA/.../sync/ServerIdentityStore.kt:138 |
| `nativeIdentitySignEnrollmentResultJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:652 | identity.sign_enrollment_result | base64 encode | androidVELA/.../sync/VaultSyncManager.kt:183 |
| `nativeIdentityOpenEnrollmentCapsuleJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:664 | identity.open_identity_capsule | rejects any plaintext that is not exactly 32 bytes; base64 out | androidVELA/.../sync/VaultSyncManager.kt:200 |
| `nativeIdentitySealSignedShareJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:677 | identity.seal_signed_share | base64 decode/encode only | androidVELA/.../core/FeatureRepositories.kt:167, :229 |
| `nativeIdentityAdmitShareJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:690 | identity.admit_share -> vela_crypto::share_envelope::admit -> vela_client_share_policy::plan_share_admission | maps the optional pin JSON to SharePin; recomputes sender_fingerprint; re-serialises the admitted pin. The `pin` argument is optional and no mobile caller ever supplies it. | androidVELA/.../core/FeatureRepositories.kt:345 (null -> share silently dropped) |
| `nativeIdentityOpenShareJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:702 | identity.open_share | base64 decode/encode | none — NativeVelaCore.kt:363 wrapper has no caller |
| `nativeIdentityForgetJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:714 | identity::forget | returns {ok: bool} | androidVELA/.../sync/ServerIdentityStore.kt:230 (return value ignored by design) |
| `nativeIdentityForgetAllJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:724 | identity::forget_all | none | none — NativeVelaCore.kt:439 wrapper has no caller |
| `nativeWebSessionChunkKeysJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:736 | vela_crypto::kdf::web_session_chunk_keys | ignores the request JSON entirely; base64-encodes each key | androidVELA/.../core/FeatureRepositories.kt:290 (rw grant; RMS wiped in finally) |
| `nativeDecryptRmsCapsuleJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:749 | aead::decrypt (via decrypt_rms_capsule_json) | requires exactly 32 plaintext bytes; returns the secret through an out JByteArray; internally base64-encodes then decodes the same RMS | androidVELA/.../sync/VaultSyncManager.kt:131 |
| `nativeDecryptEnrollmentPackageJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:762 | aead::decrypt | 32-byte key check; UTF-8 conversion | androidVELA/.../sync/VaultSyncManager.kt:1330 |
| `nativeSealShareJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:774 | vela_crypto::kem::seal_share | base64 decode/encode | androidVELA/.../core/FeatureRepositories.kt:302 (web-session envelope) |
| `nativeSplitRecoveryJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:788 | vela_crypto::shamir::split | RMS from JByteArray; base64 per share | androidVELA/.../sync/VaultSyncManager.kt:244 |
| `nativeCombineRecoveryJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:804 | vela_crypto::recovery::reconstruct_account_recovery OR shamir::reconstruct (legacy) | chooses the path from which caller-supplied binding fields are present; enforces exactly two shares on the bound path; maps channel strings to the enum; trusts the caller's recipient_bound flag; returns the RMS through an out JByteArray | androidVELA/.../sync/VaultSyncManager.kt:484 (combinePairRecovery) |
| `nativeRmsPossessionHashJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:818 | vela_crypto::recovery::rms_possession_commitment | requires exactly 32 bytes; hand-rolled JSON, bypasses the shared helper | androidVELA/.../sync/VaultSyncManager.kt:241 |
| `nativePlanRecoveryPublicationJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:836 | vela_client_recovery_policy::plan_publication_resume | 12 caller-supplied booleans/ints pass straight through; enum -> string mapping | androidVELA/.../sync/VaultSyncManager.kt:426 |
| `nativeParseImportJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:2607 | vela_import::parse_import_request | JSON in/out | androidVELA/.../core/VaultImport.kt:40; androidVELA/app/src/debug/.../InstrumentReviewActivity.kt:297 |
| `nativeRichItemsJson` | JNI | libVELA/vela-android-bridge/src/lib.rs:2617 | vela_core::rich_api::process | JSON in/out | androidVELA/.../core/RichItems.kt:42, :45, :47, :51; androidVELA/.../core/LocalVaultRepository.kt:133 |

### Apple (C ABI) — 39 exports

| Export | Kind | Rust source | Delegates to | Logic beyond conversion | Callers |
|---|---|---|---|---|---|
| `vela_ffi_version` | C | libVELA/vela-apple-bridge/src/lib.rs:324 | none — literal version string | none | iosVELA/Shared/VelaCoreFFI.swift:66 -> SettingsView.swift:248, WelcomeView.swift:31 (display only); libVELA/vela-apple-bridge/smoke/smoke.swift:13 |
| `vela_ffi_free_string` | C | libVELA/vela-apple-bridge/src/lib.rs:333 | none — drops a CString | none | iosVELA/Shared/VelaCoreFFI.swift:30 (consume helper, every call) |
| `vela_ffi_enrollment_verification_code` | C | libVELA/vela-apple-bridge/src/lib.rs:348 | vela_crypto::verification::enrollment_verification_code | null/invalid C string degrades to "" | iosVELA/Shared/VelaCoreFFI.swift:510 -> Sources/EnrollView.swift:35 |
| `vela_ffi_password_strength_json` | C | libVELA/vela-apple-bridge/src/lib.rs:358 | vela_core::calculate_password_strength | JSON decode/encode | iosVELA/Shared/VelaCoreFFI.swift:600 (wrapper has no caller) |
| `vela_ffi_encrypt_vault_json` | C | libVELA/vela-apple-bridge/src/lib.rs:375 | vela_crypto::kdf::derive + aead::encrypt | RMS as (ptr,len) beside the JSON; VaultStore parse validation; base64 out | iosVELA/Shared/VelaCoreFFI.swift:609 -> Shared/VaultRepository.swift:95, :116 |
| `vela_ffi_decrypt_vault_json` | C | libVELA/vela-apple-bridge/src/lib.rs:392 | vela_crypto::kdf::derive + aead::decrypt | RMS as (ptr,len); base64 in; UTF-8 conversion | iosVELA/Shared/VelaCoreFFI.swift:620 -> Shared/VaultRepository.swift:104, :129 |
| `vela_ffi_identity_create` | C | libVELA/vela-apple-bridge/src/lib.rs:412 | DeviceIdentity::generate + identity::register | seal key as (ptr,len); public halves + sealed blob serialised | iosVELA/Shared/VelaCoreFFI.swift:128 -> Sources/AccountViewModel.swift:109, :633, :783 |
| `vela_ffi_identity_import` | C | libVELA/vela-apple-bridge/src/lib.rs:423 | DeviceIdentity::import | base64 decode; empty string means None | iosVELA/Shared/VelaCoreFFI.swift:149 -> Shared/AccountStore.swift:260 (legacy migration) |
| `vela_ffi_identity_open` | C | libVELA/vela-apple-bridge/src/lib.rs:435 | DeviceIdentity::open | seal key as (ptr,len) | iosVELA/Shared/VelaCoreFFI.swift:160 -> Shared/AccountStore.swift:251 |
| `vela_ffi_identity_rotate_share_key` | C | libVELA/vela-apple-bridge/src/lib.rs:447 | identity.rotate_share_key + identity.seal | seal key as (ptr,len) | iosVELA/Shared/VelaCoreFFI.swift:171 -> Sources/AccountViewModel.swift:203 |
| `vela_ffi_open_rekey_capsule_json` | C | libVELA/vela-apple-bridge/src/lib.rs:464 | vela_crypto::rekey::open_rekey_capsule | previous RMS arrives base64 **inside the JSON** (audit I-2 says key material crosses as bytes); 32-byte check | none — not wrapped by VelaCoreFFI.swift |
| `vela_ffi_identity_sign_share_ek_json` | C | libVELA/vela-apple-bridge/src/lib.rs:473 | identity.sign_share_ek_binding | base64 decode/encode | iosVELA/Shared/VelaCoreFFI.swift:189 -> Sources/AccountViewModel.swift:119, :210 |
| `vela_ffi_identity_sign_json` | C | libVELA/vela-apple-bridge/src/lib.rs:480 | identity.sign_auth | base64 decode/encode | iosVELA/Shared/VelaCoreFFI.swift:182 -> Sources/AccountViewModel.swift:149, :641, :704, :822 |
| `vela_ffi_identity_open_share_json` | C | libVELA/vela-apple-bridge/src/lib.rs:487 | identity.open_share | base64 decode/encode | iosVELA/Shared/VelaCoreFFI.swift:196 (wrapper has no caller) |
| `vela_ffi_identity_seal_signed_share_json` | C | libVELA/vela-apple-bridge/src/lib.rs:498 | identity.seal_signed_share | base64 decode/encode | iosVELA/Shared/VelaCoreFFI.swift:235 -> Sources/AccountViewModel.swift:237, :368 |
| `vela_ffi_identity_admit_share_json` | C | libVELA/vela-apple-bridge/src/lib.rs:509 | identity.admit_share -> vela_crypto::share_envelope::admit -> vela_client_share_policy::plan_share_admission | pin JSON <-> SharePin; recomputes sender_fingerprint; the `pin` argument is optional and no iOS caller supplies it | iosVELA/Shared/VelaCoreFFI.swift:251 -> Sources/SharingViewModel.swift:51 (nil -> "Unverified share" row) |
| `vela_ffi_identity_enrollment_fingerprint_json` | C | libVELA/vela-apple-bridge/src/lib.rs:520 | identity.enrollment_fingerprint | handle only | iosVELA/Shared/VelaCoreFFI.swift:283 -> Sources/AccountViewModel.swift:791 |
| `vela_ffi_identity_sign_enrollment_result_json` | C | libVELA/vela-apple-bridge/src/lib.rs:529 | identity.sign_enrollment_result | base64 encode | iosVELA/Shared/VelaCoreFFI.swift:294 -> Sources/AccountViewModel.swift:801 |
| `vela_ffi_identity_open_enrollment_capsule_json` | C | libVELA/vela-apple-bridge/src/lib.rs:538 | identity.open_identity_capsule | rejects plaintext not exactly 32 bytes | iosVELA/Shared/VelaCoreFFI.swift:304 -> Sources/AccountViewModel.swift:840 |
| `vela_ffi_identity_forget_json` | C | libVELA/vela-apple-bridge/src/lib.rs:547 | identity::forget | returns {ok: bool} | iosVELA/Shared/VelaCoreFFI.swift:312 (wrapper has no caller) |
| `vela_ffi_identity_forget_all` | C | libVELA/vela-apple-bridge/src/lib.rs:552 | identity::forget_all | none | iosVELA/Shared/VelaCoreFFI.swift:316 -> Shared/AccountStore.swift:236 (clear) |
| `vela_ffi_web_session_chunk_keys_json` | C | libVELA/vela-apple-bridge/src/lib.rs:563 | vela_crypto::kdf::web_session_chunk_keys | request struct has no fields; base64-encodes each key | iosVELA/Shared/VelaCoreFFI.swift:491 -> Sources/AccountViewModel.swift:298 (rw grant) |
| `vela_ffi_encrypt_vault_chunk_json` | C | libVELA/vela-apple-bridge/src/lib.rs:580 | vela_crypto::kdf::chunk_key + rekey::seal_fleet_chunk | key_epoch defaults to 1 when absent; VaultStore parse validation | iosVELA/Shared/VelaCoreFFI.swift:358 -> Shared/SyncEngine.swift:366 (upload) |
| `vela_ffi_decrypt_vault_chunk_json` | C | libVELA/vela-apple-bridge/src/lib.rs:597 | vela_crypto::kdf::chunk_key + rekey::open_fleet_chunk | key_epoch defaults to 1; no admission decision | iosVELA/Shared/VelaCoreFFI.swift:390 — no production caller (tests only) |
| `vela_ffi_decrypt_admitted_vault_chunk_json` | C | libVELA/vela-apple-bridge/src/lib.rs:616 | vela_sync_policy::plan_sync_epoch_match; aead::is_sealed; rekey::open_fleet_chunk; vela_sync_policy::plan_chunk_download | same five additions as the Android export: sealed-header gate (not in any policy crate), aad_binding_verified := true after the open, key_epoch_positive from the integer, message formatting, admitted clock | iosVELA/Shared/VelaCoreFFI.swift:444 (OrThrow) -> Shared/SyncEngine.swift:311; iosVELA/Shared/VelaCoreFFI.swift:470 (try? wrapper) -> tests only |
| `vela_ffi_decrypt_rms_capsule_json` | C | libVELA/vela-apple-bridge/src/lib.rs:630 | aead::decrypt | accepts plaintext **>= 32** bytes and silently truncates to the first 32 (Android requires exactly 32) | iosVELA/Shared/VelaCoreFFI.swift:516 -> Sources/AccountViewModel.swift:722 |
| `vela_ffi_decrypt_enrollment_package_json` | C | libVELA/vela-apple-bridge/src/lib.rs:639 | aead::decrypt | 32-byte key check; UTF-8 conversion | iosVELA/Shared/VelaCoreFFI.swift:523 -> Shared/EnrollmentCode.swift:82 |
| `vela_ffi_split_recovery_json` | C | libVELA/vela-apple-bridge/src/lib.rs:651 | vela_crypto::shamir::split | RMS as (ptr,len); base64 per share | iosVELA/Shared/VelaCoreFFI.swift:534 -> Sources/AccountViewModel.swift:442 |
| `vela_ffi_combine_recovery_json` | C | libVELA/vela-apple-bridge/src/lib.rs:665 | recovery::reconstruct_account_recovery OR shamir::reconstruct | same path selection/enum mapping/recipient_bound trust as Android | iosVELA/Shared/VelaCoreFFI.swift:543 (legacy wrapper, no caller); iosVELA/Shared/VelaCoreFFI.swift:587 (combinePairRecovery) -> Sources/AccountViewModel.swift:616 |
| `vela_ffi_seal_contact_share_json` | C | libVELA/vela-apple-bridge/src/lib.rs:674 | recovery::seal_contact_share | assembles the outer envelope JSON itself (version/account/epoch/split/coordinate) | none — no Swift wrapper |
| `vela_ffi_open_contact_share_json` | C | libVELA/vela-apple-bridge/src/lib.rs:683 | recovery::open_contact_share / open_contact_share_response | picks the opener from a caller-supplied `response` boolean | none — no Swift wrapper |
| `vela_ffi_seal_contact_share_response_json` | C | libVELA/vela-apple-bridge/src/lib.rs:692 | recovery::seal_contact_share_response | assembles the response envelope JSON | none — no Swift wrapper |
| `vela_ffi_possession_proof_json` | C | libVELA/vela-apple-bridge/src/lib.rs:701 | recovery::rms_possession_sign + rms_possession_commitment | RMS arrives base64 in JSON; computes both the commitment and the proof | none — no Swift wrapper |
| `vela_ffi_generate_recovery_request_json` | C | libVELA/vela-apple-bridge/src/lib.rs:709 | vela_crypto::kem::generate_keypair | base64 encode of both halves | none — no Swift wrapper |
| `vela_ffi_rms_possession_hash_json` | C | libVELA/vela-apple-bridge/src/lib.rs:716 | recovery::rms_possession_commitment | RMS as (ptr,len); JSON built inline | iosVELA/Shared/VelaCoreFFI.swift:594 -> Sources/AccountViewModel.swift:446 |
| `vela_ffi_plan_recovery_publication_json` | C | libVELA/vela-apple-bridge/src/lib.rs:733 | vela_client_recovery_policy::plan_publication_resume | 12 caller-supplied facts pass through; enum -> string mapping | iosVELA/Shared/VelaCoreFFI.swift:91 -> Sources/AccountViewModel.swift:996 |
| `vela_ffi_seal_share_json` | C | libVELA/vela-apple-bridge/src/lib.rs:744 | vela_crypto::kem::seal_share | base64 decode/encode | iosVELA/Shared/VelaCoreFFI.swift:324 -> Sources/AccountViewModel.swift:309 |
| `vela_ffi_rich_items_json` | C | libVELA/vela-apple-bridge/src/lib.rs:2397 | vela_core::rich_api::process | JSON in/out | iosVELA/Shared/VelaCoreFFI.swift:9 -> Shared/VaultMerge.swift:60, :88; Sources/VaultViewModel.swift:220, :238, :287, :302, :531, :555, :630 |
| `vela_ffi_parse_import_json` | C | libVELA/vela-apple-bridge/src/lib.rs:2407 | vela_import::parse_import_request | JSON in/out | iosVELA/Shared/VelaCoreFFI.swift:20 -> Sources/VaultViewModel.swift:490 |

### WASM (wasm_bindgen) — 9 exports

| Export | Kind | Rust source | Delegates to | Logic beyond conversion | Callers |
|---|---|---|---|---|---|
| `vela_wasm_version` | wasm_bindgen | libVELA/vela-wasm-bridge/src/lib.rs:300 | none — literal version string | none | none — not imported by webVELA/src/vela.ts |
| `generate_ephemeral_keypair` | wasm_bindgen | libVELA/vela-wasm-bridge/src/lib.rs:307 | vela_crypto::kem::generate_keypair | base64 encode | webVELA/src/vela.ts:28 -> webVELA/src/main.ts:666 |
| `generate_signing_keypair` | wasm_bindgen | libVELA/vela-wasm-bridge/src/lib.rs:314 | vela_crypto::signing::generate_keypair | base64 encode; secret stays in JS/WASM memory | webVELA/src/vela.ts:32 -> webVELA/src/main.ts:667 |
| `create_auth_signature_json` | wasm_bindgen | libVELA/vela-wasm-bridge/src/lib.rs:321 | vela_crypto::signing::auth_message + signing::sign | decodes caller-supplied sk; JSON in/out | webVELA/src/vela.ts:37 -> webVELA/src/main.ts:451 (RW token request) |
| `open_share_json` | wasm_bindgen | libVELA/vela-wasm-bridge/src/lib.rs:328 | vela_crypto::kem::open_share | base64 decode; UTF-8 conversion | webVELA/src/vela.ts:43 -> webVELA/src/main.ts:601 (grant capsule -> chunk keys) |
| `open_link_json` | wasm_bindgen | libVELA/vela-wasm-bridge/src/lib.rs:336 | vela_crypto::link::open_link | decodes URL-safe link key, optional salt/passphrase; treats empty passphrase as absent | webVELA/src/vela.ts:61 -> webVELA/src/send.ts:182 |
| `encrypt_vault_chunk_json` | wasm_bindgen | libVELA/vela-wasm-bridge/src/lib.rs:343 | vela_crypto::rekey::seal_fleet_chunk | per-chunk key (no RMS in this bridge by design); epoch Option -> 1 | webVELA/src/vela.ts:119 -> webVELA/src/main.ts:574 (save) |
| `decrypt_vault_chunk_json` | wasm_bindgen | libVELA/vela-wasm-bridge/src/lib.rs:350 | vela_crypto::rekey::open_fleet_chunk | **no admission policy at all**: no epoch-match call, no rollback baseline, no sealed-header gate, no admitted-clock return | webVELA/src/vela.ts:91 -> webVELA/src/main.ts:478 (pullRemoteVault) |
| `password_strength_json` | wasm_bindgen | libVELA/vela-wasm-bridge/src/lib.rs:356 | vela_core::calculate_password_strength | JSON in/out | none — not imported by webVELA/src/vela.ts |
## Caller tables

### Android (Kotlin, `androidVELA/app`)

All access goes through the `NativeVelaCore` object
(`app/src/main/java/com/vela/android/core/NativeVelaCore.kt`), which holds the
`external fun` declarations (`:635-667`). Column 2 is the production call site;
`callNative` (`:630-633`) converts any thrown/JSON `error` into
`IllegalStateException("Native VELA bridge call failed: ...")`.

| Export (Kotlin wrapper) | Call site | What the caller does with the result | Verdict |
|---|---|---|---|
| `nativeVersion` (`:27`) | `core/SharedCoreStatus.kt:12` | display only | harmless |
| `nativeEnrollmentVerificationCode` (`:194`) | `ui/screens/EnrollDeviceScreen.kt:94` | shows the 6-digit code before importing the code | null -> no code shown |
| `nativeEncryptVaultJson` (`:67`) | `security/EncryptedVaultStore.kt:84` | persists the sealed local blob; null -> throw | writes only on success |
| `nativeDecryptVaultJson` (`:78`) | `security/EncryptedVaultStore.kt:53` | unlocks the local blob; null -> throw | no plaintext fallback |
| `nativeEncryptVaultChunkJson` (`:94`) | `sync/VaultSyncManager.kt:1061`; `core/LocalVaultRepository.kt:102` | base64-decodes and PUTs with the same clock/epoch it sealed | clock settled before sealing |
| `nativeDecryptAdmittedVaultChunkJson` (`:151`) | `sync/VaultSyncManager.kt:988` | null -> `error(...)`; decodes, merges, and only then `replaceAllAdmitted` records floors (`:594, :678, :695, :717, :748`) | the only production download path |
| `nativeDecryptVaultChunkJson` (`:121`) | `core/LocalVaultRepository.kt:116` (`decryptSyncedVault`) | nothing: **no caller anywhere** | latent non-admitting path |
| `nativeIdentityCreateJson` (`:272`) | `sync/ServerIdentityStore.kt:68, :108` | persists the sealed blob, registers the public halves | private keys never on the JVM heap |
| `nativeIdentityImportJson` (`:278`) | `sync/ServerIdentityStore.kt:151, :257` | legacy plaintext-key migration, then deletes them | one-time read |
| `nativeIdentityOpenJson` (`:293`) | `sync/ServerIdentityStore.kt:177` | reopens at unlock/startup | |
| `nativeIdentityRotateShareKeyJson` (`:427`) | `sync/ServerIdentityStore.kt:190` | registers the rotated share key | |
| `nativeIdentitySignJson` (`:299`) | `sync/VaultSyncManager.kt:856` | device auth signature in the login request | |
| `nativeIdentitySignShareEkJson` (`:311`) | `sync/ServerIdentityStore.kt:74, :114, :194`; `sync/VaultSyncManager.kt:823` | share-key binding signature sent to the server | |
| `nativeIdentityEnrollmentFingerprintJson` (`:330`) | `sync/ServerIdentityStore.kt:138` | rendered for out-of-band comparison | handle-only API, no key bytes |
| `nativeIdentitySignEnrollmentResultJson` (`:340`) | `sync/VaultSyncManager.kt:183` | proves the joining device holds the key | |
| `nativeIdentityOpenEnrollmentCapsuleJson` (`:352`) | `sync/VaultSyncManager.kt:200` | obtains the RMS after enrollment | 32-byte check in Rust |
| `nativeIdentitySealSignedShareJson` (`:375`) | `core/FeatureRepositories.kt:167, :229` | uploads the capsule; bumps the record revision | |
| `nativeIdentityAdmitShareJson` (`:403`) | `core/FeatureRepositories.kt:345` | null -> the share is silently dropped from the list; **never passes a `pin`** | F6 |
| `nativeIdentityOpenShareJson` (`:363`) | none | | dead wrapper |
| `nativeIdentityForgetJson` (`:435`) | `sync/ServerIdentityStore.kt:230` | sign-out / reset; return value ignored on purpose | |
| `nativeIdentityForgetAllJson` (`:439`) | none | | dead wrapper |
| `nativeWebSessionChunkKeysJson` (`:235`) | `core/FeatureRepositories.kt:290` | puts per-chunk keys in the rw session envelope; RMS wiped in `finally` | RMS never leaves the device |
| `nativeDecryptRmsCapsuleJson` (`:201`) | `sync/VaultSyncManager.kt:131` | RMS after recovery; wipes the out array on error | |
| `nativeDecryptEnrollmentPackageJson` (`:219`) | `sync/VaultSyncManager.kt:1330` | enrollment payload | |
| `nativeSealShareJson` (`:445`) | `core/FeatureRepositories.kt:302` | KEM-seals the web-session envelope to the browser key | |
| `nativeSplitRecoveryJson` (`:462`) | `sync/VaultSyncManager.kt:244` | 2-of-3 shares handed to cloud / server / contact | |
| `nativeCombineRecoveryJson` (`:478`, `:493`) | `sync/VaultSyncManager.kt:484` | unlocks the vault after recovery; null -> `error` | `recipient_bound=false` always |
| `nativeRmsPossessionHashJson` (`:543`) | `sync/VaultSyncManager.kt:241` | stages the commitment with the server share | |
| `nativePlanRecoveryPublicationJson` (`:30`) | `sync/VaultSyncManager.kt:426` | drives the next journal step | 12 caller facts |
| `nativePasskeyKeygenJson` (`:566`) | `security/passkey/PasskeyAuthenticator.kt:84` | stores the fresh scalar in the sealed vault | |
| `nativePasskeyAuthDataJson` (`:582`) | `PasskeyAuthenticator.kt:89, :171` | composes authenticatorData; **UV decided in Kotlin** | F5 |
| `nativePasskeyAttestationObjectJson` (`:605`) | `PasskeyAuthenticator.kt:96` | registration response | |
| `nativePasskeySignJson` (`:616`) | `PasskeyAuthenticator.kt:180` | assertion signature | |
| `nativeOpenRekeyCapsuleJson` | none | no Kotlin `external` is declared for it | dead export |
| `nativeParseImportJson` (`:18`) | `core/VaultImport.kt:40`; debug `app/src/debug/.../InstrumentReviewActivity.kt:297` | import preview | |
| `nativeRichItemsJson` (`:12`) | `core/RichItems.kt:42, :45, :47, :51`; `core/LocalVaultRepository.kt:133` | schema validate/mutate/repair/merge, capabilities probe | |
| Android C ABI (`vela_*`) | in-crate Rust tests only (`lib.rs:1981, :1987, :2432, :2446`) | | no production consumer |

### iOS (Swift, `iosVELA`)

All access goes through `enum VelaCoreFFI`
(`iosVELA/Shared/VelaCoreFFI.swift`); every returned pointer is freed by
`consume` (`:28-32`). Most wrappers return `nil` on refusal, so a rejection and a
missing handle look alike unless the caller uses `decryptVaultChunkAdmittedOrThrow`.

| Export (Swift wrapper) | Call site | What the caller does with the result | Verdict |
|---|---|---|---|
| `vela_ffi_version` (`:66`) | `Sources/SettingsView.swift:248`, `Sources/WelcomeView.swift:31` | display only | harmless |
| `vela_ffi_enrollment_verification_code` (`:510`) | `Sources/EnrollView.swift:35` | shows the out-of-band code | |
| `vela_ffi_encrypt_vault_json` (`:609`) | `Shared/VaultRepository.swift:95, :116` | writes the sealed local vault | |
| `vela_ffi_decrypt_vault_json` (`:620`) | `Shared/VaultRepository.swift:104, :129` | `guard let ... else throw` | refuses to continue on failure |
| `vela_ffi_identity_create` (`:128`) | `Sources/AccountViewModel.swift:109, :633, :783` | registers the public halves, persists `sealed` | |
| `vela_ffi_identity_import` (`:149`) | `Shared/AccountStore.swift:260` | legacy migration; deletes plaintext keys after | |
| `vela_ffi_identity_open` (`:160`) | `Shared/AccountStore.swift:251` | reopen a stored identity | |
| `vela_ffi_identity_rotate_share_key` (`:171`) | `Sources/AccountViewModel.swift:203` | registers the rotated key | |
| `vela_ffi_identity_sign_json` (`:182`) | `Sources/AccountViewModel.swift:149, :641, :704, :822` | auth challenge signature | |
| `vela_ffi_identity_sign_share_ek_json` (`:189`) | `Sources/AccountViewModel.swift:119, :210` | share-key binding signature | |
| `vela_ffi_identity_open_share_json` (`:196`) | none | | dead wrapper |
| `vela_ffi_identity_seal_signed_share_json` (`:235`) | `Sources/AccountViewModel.swift:237, :368` | uploads the capsule | |
| `vela_ffi_identity_admit_share_json` (`:251`) | `Sources/SharingViewModel.swift:51` | nil -> row rendered as "Unverified share"; `accept` then refuses; **no `pin`** | F6 |
| `vela_ffi_identity_enrollment_fingerprint_json` (`:283`) | `Sources/AccountViewModel.swift:791` | shown for comparison | |
| `vela_ffi_identity_sign_enrollment_result_json` (`:294`) | `Sources/AccountViewModel.swift:801` | proves possession after enrollment | |
| `vela_ffi_identity_open_enrollment_capsule_json` (`:304`) | `Sources/AccountViewModel.swift:840` | obtains the RMS | |
| `vela_ffi_identity_forget_json` (`:312`) | none | | dead wrapper |
| `vela_ffi_identity_forget_all` (`:316`) | `Shared/AccountStore.swift:236` | sign-out / reset | |
| `vela_ffi_web_session_chunk_keys_json` (`:491`) | `Sources/AccountViewModel.swift:298` | rw session envelope of per-chunk keys | |
| `vela_ffi_encrypt_vault_chunk_json` (`:358`) | `Shared/SyncEngine.swift:366` | upload with the clock settled at `:365` | clock before seal |
| `vela_ffi_decrypt_vault_chunk_json` (`:390`) | tests only (`Tests/Phase4Tests.swift:57, :62, :67`) | | no production caller |
| `vela_ffi_decrypt_admitted_vault_chunk_json` (`:444` OrThrow / `:470` `try?`) | `Shared/SyncEngine.swift:311` (OrThrow); `try?` wrapper only in tests | refuses the sync on any refusal (`:324-330`); baselines recorded only after `repo.save` (`:341-346`) | the only production download path; F7 duplicate pre-check at `:298` |
| `vela_ffi_decrypt_rms_capsule_json` (`:516`) | `Sources/AccountViewModel.swift:722` | RMS after recovery | |
| `vela_ffi_decrypt_enrollment_package_json` (`:523`) | `Shared/EnrollmentCode.swift:82` | decodes the v2 enrollment package | |
| `vela_ffi_split_recovery_json` (`:534`) | `Sources/AccountViewModel.swift:442` | 2-of-3 shares | |
| `vela_ffi_combine_recovery_json` (`:543` legacy, `:587` pair) | legacy: none; pair -> `Sources/AccountViewModel.swift:616` | unlocks after recovery; nil -> throw | `recipient_bound=false` always |
| `vela_ffi_rms_possession_hash_json` (`:594`) | `Sources/AccountViewModel.swift:446` | stages the commitment | |
| `vela_ffi_plan_recovery_publication_json` (`:91`) | `Sources/AccountViewModel.swift:996` | drives the next journal step | 12 caller facts |
| `vela_ffi_seal_share_json` (`:324`) | `Sources/AccountViewModel.swift:309` | seals the web-session envelope | |
| `vela_ffi_password_strength_json` (`:600`) | none | | dead wrapper |
| `vela_ffi_open_rekey_capsule_json`, `seal/open/seal_response_contact_share_json`, `possession_proof_json`, `generate_recovery_request_json` | none | no Swift wrapper at all | F12; iOS recovery therefore supports only cloud+server |
| `vela_ffi_rich_items_json` (`:9`) | `Shared/VaultMerge.swift:60, :88`; `Sources/VaultViewModel.swift:220, :238, :287, :302, :531, :555, :630` | rich-item validate/mutate/repair/merge | |
| `vela_ffi_parse_import_json` (`:20`) | `Sources/VaultViewModel.swift:490` | import preview | |

### Web (TypeScript, `webVELA/src`)

| Export (TS wrapper) | Call site | What the caller does with the result | Verdict |
|---|---|---|---|
| `generate_ephemeral_keypair` (`vela.ts:28`) | `main.ts:666` | KEM half of the session key; public half goes into the link QR | |
| `generate_signing_keypair` (`vela.ts:32`) | `main.ts:667` | `web_vk` in the link, `sk` kept in the page | |
| `create_auth_signature_json` (`vela.ts:37`) | `main.ts:451` | authenticates the RW token request | |
| `open_share_json` (`vela.ts:43`) | `main.ts:601` | opens the grant capsule -> per-chunk keys | RMS never reaches the page |
| `open_link_json` (`vela.ts:61`) | `send.ts:182` | opens a one-off link payload | key comes from the URL fragment |
| `encrypt_vault_chunk_json` (`vela.ts:119`) | `main.ts:574` | save path; clock settled at `:573` | bound correctly |
| `decrypt_vault_chunk_json` (`vela.ts:91`) | `main.ts:478` | appends plaintext to the merged vault | **no admission gate** (F1) |
| `vela_wasm_version`, `password_strength_json` | none | not imported by `vela.ts` | dead exports |

### Desktop (Tauri + gpui) — a process boundary, not an FFI one

`desktopVELA/src-tauri/src/commands/*.rs` exposes **109** `#[tauri::command]`
functions (17 modules: `vault.rs` 27, `devices.rs` 14, `recovery.rs` 11,
`settings.rs` 10, `session.rs` 9, `window.rs` 6, `biometric.rs` 5, `sharing.rs` 5,
`passkey_provider.rs` 4, `sync.rs` 4, `share_link.rs` 3, `web_session.rs` 3,
`audit.rs` 2, `clipboard.rs` 2, `totp.rs` 2, `ipc.rs` 1, `rekey.rs` 1). Every one
is a thin argument/state adapter over `vela_desktop_core`. The TS front end makes
58 `invoke(` calls from 20 files and never touches key material; the gpui front end
makes 245 `vela_desktop_core::` references in-process. Rust here calls
`vela-sync-policy` directly rather than through a bridge:

| Desktop path | Location | Note |
|---|---|---|
| `reject_rollback` | `vela-desktop-core/src/sync.rs:526-546` | calls `plan_chunk_download` with `aad_binding_verified: true`, `key_epoch_positive: true` as **literals**, before the open at `:1090` (F3) |
| chunk open | `vela-desktop-core/src/sync.rs:1090` | `open_fleet_chunk` directly; no `is_sealed` gate (F2) |
| epoch adoption | `vela-desktop-core/src/sync.rs:355-360` | `plan_epoch_adoption` with caller-computed `server_epoch_is_next` |
| share admission | `vela-desktop-core/src/sharing.rs:195, :261, :784` | uses `vela-client-share-policy` with a stored generation (the only client that pins) |

## Type mapping

| Boundary | Request | Secret bytes in | Response | Errors | Optionals |
|---|---|---|---|---|---|
| Android JNI | `JString` UTF-8 JSON built with `org.json` | `JByteArray` (RMS, seal key), copied into a zeroizing buffer | `jstring` JSON; allocation failure -> null pointer | never a Java exception: JSON-returning calls always carry `{"error":"..."}` (the version and verification-code calls return bare strings); Kotlin re-raises as `IllegalStateException` | absent key (`last_seen_lamport`) or `JSONObject.NULL` (`split_id`) -> `Option`; `i64`/`u64` as JSON numbers |
| Android byte results | n/a | — | out-parameter `JByteArray` written via `set_byte_array_region` after `u8 -> i8`; JSON carries only `{"ok":true}` | | |
| Apple C ABI | `*const c_char` NUL-terminated JSON (an interior NUL truncates the payload) | `(*const u8, len)` beside the JSON; empty `Data` -> `(null, 0)` -> "RMS must be 32 bytes" | `*mut c_char` owned by Rust, freed with `vela_ffi_free_string` | `{"error":"..."}`; `CString::new` failure falls back to an empty string, losing the message | omitted key -> `Option`; `key_epoch` defaults to 1 |
| Apple byte results | n/a | — | none: the recovered RMS returns base64 inside JSON (no out-parameter) | | |
| WASM | `&str` UTF-8 JSON | base64 inside JSON (per-chunk keys, ephemeral `sk`, link key); never the RMS | `String` JSON | `{"error":"..."}` with a successful WASM call; the TS wrapper throws (`vela.ts:21-25`) | `null`/absent for `passphrase`, `salt_b64`; `epoch: Option<u64>` -> 1 |
| Tauri IPC | `invoke(cmd, args)` JSON | never crosses (keys stay in the Rust process) | JSON | rejected promise with a `String` | serde `Option` via the JSON codec |

Divergences that matter for a single statement across bridges: the signature field
is `signature` on Android (`lib.rs:1232`) and `signature_b64` on Apple (`lib.rs:877`);
the RMS capsule is required to be exactly 32 bytes on Android (`lib.rs:1465`) but is
accepted at `>= 32` and truncated on Apple (`lib.rs:1236-1241`); `previous_rms`
arrives as a JSON integer array on Android (`lib.rs:536`) and as base64 text on Apple
(`lib.rs:892`) — both place key material inside the JSON envelope that audit I-2 says
should carry bytes.

## Findings

### F1 (high) The web client reads server chunks with no admission gate

`libVELA/vela-wasm-bridge/src/lib.rs` has no admitted-chunk export; its only chunk
entry points are `encrypt_vault_chunk_json` (`:343`) and `decrypt_vault_chunk_json`
(`:350`). `webVELA/src/main.ts:478-484` decrypts each chunk with `authed.epoch`, and
`webVELA/src/api.ts:148` assigns `this.epoch = m.epoch` from the server's own manifest
response. No baseline is kept, and `main.ts:477` skips (`continue`) any chunk the
server omits. `plan_chunk_download`, `plan_sync_epoch_match` and the sealed-header gate
are unreachable on this path. N5-N7 must treat web as a caller that never reaches
admission.

### F2 (high) The sealed-ciphertext gate exists only in the mobile bridges — and the desktop path lacks it

`android lib.rs:1011` and `apple lib.rs:1160` both refuse blobs without the `VAE1`
header. `vela_crypto::aead::open_vault_chunk` (`vela-crypto/src/aead.rs:55-66`)
decrypts an unsealed blob and ignores `chunk_id` and `lamport_clock`, and the desktop
download path calls `open_fleet_chunk` directly (`sync.rs:1090`) with no `is_sealed`
check. Because `reject_rollback` accepts any clock at or above the recorded floor, a
server can relabel a pre-C-2 unsealed chunk with a high clock and have desktop admit it
— exactly the rollback the mobile gate blocks. Consequence for N2: the gate has to move
into `vela-sync-policy`/`vela-crypto` (and desktop must call it) before the bridges can
be shown to be pure conversions.

### F3 (high) `aad_binding_verified` is a literal on the desktop path

`desktopVELA/vela-desktop-core/src/sync.rs:531-538` passes `aad_binding_verified: true`
and `key_epoch_positive: true` and runs *before* the AEAD open at `:1090`. On mobile the
flag is derived after a successful open (`android:1069`, `apple:1200`). This is the fact
`17-universal-chunk-admission.md` says its theorem does not establish ("A caller
providing an incorrect flag is not made safe by a correct policy kernel"). Desktop also
never calls `plan_sync_epoch_match`.

### F4 (medium) Android passkey primitives are a hand-mirrored copy, not a delegation

`libVELA/vela-android-bridge/src/passkey.rs:1-27` says the WebAuthn layouts are
"line-for-line ports" of `desktopVELA/vela-desktop-core/src/passkey.rs` and the module
uses `p256`/`ciborium`/`sha2` directly; it never calls `vela-core` or `vela-crypto`.
Four exports therefore cannot be proved thin. The desktop `PresenceToken` linear type
cannot cross JNI, so "one ceremony per approval" is a Kotlin obligation.

### F5 (medium) The WebAuthn UV bit is decided in Kotlin

`PasskeyAuthenticator.kt:171-174` computes `flags = FLAG_UP or (if (verified) FLAG_UV else 0)`
and `lib.rs:599` forwards `flags` verbatim into the authenticator data. The bridge
cannot check the user-verification decision that relying parties trust.

### F6 (medium) Share-envelope pinning is inert on both mobile clients

`androidVELA/.../FeatureRepositories.kt:345-347` and
`iosVELA/Sources/SharingViewModel.swift:51-53` call `identityAdmitShare` without a pin,
and neither app persists a `SharePin`. Every mobile share is admitted as first contact,
so a swapped sender key for an existing lineage would be accepted; only the desktop
path consults `vela-client-share-policy` with a stored generation.

### F7 (medium) Epoch and manifest-floor decisions are duplicated in native code

Android: `requireMatchingSyncEpoch` (`VaultSyncManager.kt:43-49`, called at `:581, :627,
:658`), `rejectRollback` (`:912-924`), `requireReadableBaseline` (`:927-933`). iOS:
`SyncEngine.swift:298-302` and `rejectRollback` (`:233-249`). Doc 18 calls the iOS
manifest floor a deliberate, stricter difference, but it means three implementations of
one predicate have to stay aligned and admission is not reached only through the bridge.

### F8 (medium) Security facts are supplied by the caller and passed straight through

`recipient_bound` is taken from the request and fed to the verified recovery policy
(`android lib.rs:1548`, `apple lib.rs:1317, :1572`). `plan_publication_resume` receives
12 caller booleans/integers. Desktop computes `server_epoch_is_next` itself
(`sync.rs:359`), which doc 18 (`:65`) still records as caller-supplied. The verified
kernels are only as strong as these observations.

### F9 (medium) Error identity is recovered by matching an English substring

`NativeVelaCore.kt:716-728` and `SyncEngine.swift:319` branch on
`"legacy unsealed chunk ciphertext cannot be admitted"`. The ABI returns no error code,
so rewording a Rust message silently changes client security behaviour.

### F10 (low) Refusal semantics differ per platform

Android returns a JSON envelope for every call that can fail and Kotlin throws; Apple
returns `nil` from most wrappers (only `AdmissionError.refused`, `VelaCoreFFI.swift:412-459`,
preserves the reason); WASM returns `{"error":...}` as a successful call and only the TS
wrapper throws. A thinness statement has to be made per boundary, and caller analyses
must model three refusal semantics.

### F11 (low) ABI divergences between the two mobile bridges

Signature field naming, RMS-capsule length handling (exact 32 vs `>= 32` + truncate),
`previous_rms` encoding, and asymmetrical surfaces (Apple-only trusted-contact envelopes
and possession proof; Android-only passkey primitives). N2a-c cannot share one statement
until these are reconciled; the truncation difference has a direct security reading.

### F12 (low) Dead and unreachable ABI surface

Android: `vela_encrypt_bytes` (`lib.rs:885`, no caller, no error message on failure),
`nativeOpenRekeyCapsuleJson` (`:569`, no Kotlin `external`), Kotlin wrappers
`identityOpenShare` (`:363`) and `identityForgetAll` (`:439`), and the non-admitting
`decryptSyncedVault` (`LocalVaultRepository.kt:109`) which nothing calls. Apple:
`open_rekey_capsule_json`, the three contact-share functions, `possession_proof_json`,
`generate_recovery_request_json`, plus the unused Swift wrappers
`password_strengthJSON`, `identityOpenShare`, `identityForget`, legacy `combineRecovery`.
Each is an open door to decryption without admission for a future caller.

## What is unverified

- JNI symbol resolution and `jni`-crate behaviour: not executed (no build). Exports are
  read from source and matched by inspection to `com.vela.android.core.NativeVelaCore`.
- Swift was not compiled (Linux host); all iOS call sites are textual.
- `webVELA/src/wasm/*.js` is a build artefact and absent from the tree, so the
  TS <-> wasm calling convention is taken from the `#[wasm_bindgen]` signatures only.
- Out-of-tree consumers of the Apple XCFramework (if any) are unknown, so "no caller"
  for those six exports is scoped to this repository.
- The desktop command count (109) comes from attribute scanning; the gpui front end's
  245 `vela_desktop_core::` references were not individually classified.
- Whether the desktop `is_sealed` gap (F2) is reachable in practice depends on the
  server-side chunk store retaining pre-C-2 blobs; not tested here.

## Suggested follow-ups

1. **N2a-c**: use these tables as the row set. For each export, either state the proof
   obligation (pure conversion) or list it as logic that must move first — in practice
   the sealed-header gate (F2), the passkey ports (F4), and the two capsule-length
   normalisations (F11).
2. **N5-N7**: treat `webVELA/src/main.ts:478` as the first gap to close (add an admitted
   chunk export to the wasm bridge, or move the web client onto one), then the desktop
   `reject_rollback` literals (F3) and `is_sealed` (F2).
3. Add machine-readable error codes to the three bridges so `mapAdmittedChunkFailure`
   and `SyncEngine` stop matching English text (F9).
4. Decide whether the mobile clients should persist `SharePin` (F6) or whether the pin
   mechanism is desktop-only by design — either way the docs should say so.
5. Remove or document the dead ABI surface (F12) so later caller analysis does not have
   to re-derive that it is unreachable.

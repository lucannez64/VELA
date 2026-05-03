# Android App Plan: VELA Native Android With Offline-First Vault and Full Desktop Parity

## Summary

Build a new native Android app in Kotlin/Jetpack Compose with a shared Rust core exposed through JNI/UniFFI. Android will support all desktop app features, plus Android system autofill through `AutofillService` and app-side autofill lifecycle integration through `AutofillManager`.

Default behavior is local-first: the app can create, unlock, edit, search, and autofill a vault without any server. Server sync, device enrollment, sharing, recovery, audit sync, and breach checks are optional online features enabled when `server_url` is configured.

## Architecture

Create a new repo module:

- `androidVELA/`
- Kotlin Android app using Gradle, Jetpack Compose, Room/DataStore, WorkManager, BiometricPrompt, Android Keystore, and Autofill APIs.
- `libVELA/vela-core/` new shared Rust core crate extracted from desktop logic.
- `libVELA/vela-crypto/` remains the low-level crypto crate.
- `desktopVELA/src-tauri` should gradually depend on the same shared core to avoid drift, but Android milestone 1 can copy/extract logic first and refactor desktop after parity tests pass.

Core layering:

- `vela-crypto`: AEAD, KDF, KEM/signing, Shamir, ORAM.
- `vela-core`: vault models, serialization, item CRUD, search/domain matching, password generation, sync merge, tombstones, audit log encryption, sharing capsule helpers, breach hash helpers.
- `androidVELA`: UI, Android storage, Android Keystore, BiometricPrompt, AutofillService, WorkManager, network client, permissions/settings.

## Public Interfaces And Types

Define stable Rust/Kotlin bridge DTOs matching desktop semantics:

- `VaultItemDto`
  - `Login`, `CreditCard`, `SecureNote`, `Identity`, `FileBlob`, `BreachMonitor`
  - Same fields as desktop `VaultItem`, including `favorite`, `shared`, `share_recipient`, timestamps, and `last_modified_device`.
- `VaultStoreDto`
  - `items: List<VaultItemDto>`
  - `tombstones: List<TombstoneDto>`
- `SessionStatusDto`
  - `active`, `remaining_seconds`, `device_id`, `user_id`, `lock_state`
- `SettingsDto`
  - Android equivalent of desktop settings, replacing desktop-only fields:
  - Keep: lock timeout, clipboard clear seconds, biometric reveal requirement, sync startup/background interval, theme, compact list, user id, server url.
  - Add: `autofill_enabled_hint_seen`, `inline_suggestions_enabled`, `offline_mode`.
  - Drop: desktop quick search shortcut and extension connection state.
- `SyncStatusDto`
  - `last_synced`, `conflicts`, `error`, `uploaded_chunks`.
- `AutofillCandidateDto`
  - `item_id`, `label`, `username`, `domain`, `has_totp`, `item_type`.
- `AutofillFillDto`
  - login username/password/TOTP fields and credit card fields.

Expose bridge methods:

- Vault/session:
  - `create_vault(use_biometric: Boolean, fallback_password: String?)`
  - `unlock_with_biometric()`
  - `unlock_with_password(password)`
  - `lock()`
  - `get_items()`, `get_item(id)`, `add_item(item)`, `update_item(item)`, `delete_item(id)`
  - `search(query)`, `search_by_domain(domain)`, `get_items_by_type(type)`
- Security:
  - `generate_password(options)`
  - `password_strength(password)`
  - `get_vault_health()`
- Sync/server:
  - `set_server_url(url)`
  - `trigger_sync()`
  - `resolve_conflict(item_id, use_local)`
  - `register_or_authenticate_device()`
  - `get_devices()`, `revoke_device(id)`
- Sharing/recovery/audit:
  - mirror desktop commands for inbox, linked shares, WebAuthn recovery, recovery shares, and audit events.
- Autofill:
  - `find_autofill_candidates(package_name, web_domain, hints)`
  - `get_autofill_secret(item_id, requested_fields)`
  - `save_autofill_capture(captured_fields, package_name, web_domain)`

## Android Storage And Security

Use Android Keystore as the primary protection layer:

- Generate an AES-GCM Keystore key named `VELA_RMS_ANDROID`.
- Require user authentication with `setUserAuthenticationRequired(true)`.
- Use BiometricPrompt for normal unlock and reveal flows.
- Store RMS encrypted by the Keystore key in app-private storage.
- Password fallback stores RMS encrypted with a Rust KDF-derived key plus random salt, in app-private storage.
- Keep decrypted RMS only in memory while the session is active.
- Clear in-memory session on timeout, explicit lock, app background timeout, or process shutdown where possible.
- Store encrypted vault file in app-private storage, equivalent to desktop `vault.enc`.
- Store settings in DataStore.
- Store sync metadata/conflicts in app-private files or Room tables.

## Offline-First Behavior

Default setup path:

1. User opens Android app.
2. App offers biometric vault creation first.
3. If biometric/Keystore auth is unavailable or user chooses fallback, create local password-protected vault.
4. No server URL is required.
5. User can add/edit/delete/search/autofill items immediately.
6. Sync and server-backed features are shown but disabled until a server URL is configured.

When server becomes available:

- Authenticate/register using existing VELA server APIs.
- Preserve existing local vault.
- First sync uploads local encrypted chunks if server has no vault.
- If server has vault data, run merge with tombstones and conflict detection.
- Never overwrite non-empty server data with an empty local vault.

## AutofillService Design

Implement `VelaAutofillService : AutofillService`.

Manifest requirements:

- Declare service with `android.permission.BIND_AUTOFILL_SERVICE`.
- Add `android.service.autofill` metadata XML.
- Add in-app button that launches `Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE`.

`onFillRequest` flow:

1. Read latest `AssistStructure`.
2. Traverse nodes and classify fields:
   - Login username/email.
   - Password.
   - TOTP/OTP.
   - Credit card number, expiration, CVV, cardholder.
3. Resolve origin:
   - Prefer `webDomain` from structure nodes where available.
   - Fall back to package name mapping for native apps.
4. If vault is locked:
   - Return a `FillResponse` with authentication intent to unlock VELA.
   - After unlock, return authenticated datasets.
5. If unlocked:
   - Query `find_autofill_candidates`.
   - Return one dataset per matching login/card.
   - Support inline suggestions where available.
6. For ambiguous fields, fill only exact/confident mappings.

`onSaveRequest` flow:

1. Parse changed field values from `SaveRequest`.
2. Detect login creation/update:
   - username/email + password.
   - optional TOTP.
3. Detect credit card save:
   - card number + expiry, optional CVV/cardholder.
4. Launch confirmation activity.
5. Save as new item or update matched item.
6. Record audit event locally.
7. Queue background sync if server is configured.

`AutofillManager` use inside VELA app:

- Use it for VELA’s own Compose/input fields where manual autofill lifecycle is useful.
- It is not the provider mechanism; provider work lives in `AutofillService`.

## UI Feature Parity

Compose screens:

- Welcome/setup.
- Biometric/password unlock gate.
- Vault browser with item filters.
- Item detail/edit for logins, cards, notes, identities, files, breach monitor entries.
- Add item modal/screen.
- Password generator.
- Conflict resolution.
- Devices screen.
- Sharing screen.
- Audit log screen.
- Trusted contact/recovery setup.
- Breach monitor screen.
- Settings screen.
- Autofill enablement screen with direct system settings launch.
- Session expired overlay.

Android-specific UX:

- Bottom navigation or navigation rail depending on width.
- Floating add button for vault item creation.
- Secure reveal actions guarded by BiometricPrompt when setting requires it.
- Clipboard copy with automatic clear.
- Autofill service status card in Settings.

## Networking And Sync

Implement Android HTTP client against existing server APIs:

- `/health`
- `/auth/challenge`
- `/auth/verify`
- `/account/register`
- `/vault/sync`
- `/vault/chunk/{id}`
- `/vault/oram/{tree_id}/path/{leaf}`
- `/devices`
- `/device/enroll`
- `/device/capsule`
- `/device/revoke`
- `/share/*`
- `/recovery/*`

Use WorkManager:

- Periodic background sync when unlocked or when a refresh token/session token is valid.
- One-shot sync after item changes.
- Network constraints: only run server sync when connected.
- If offline, queue local changes and keep app fully usable.

## Implementation Phases

1. Scaffold Android project:
   - `androidVELA`
   - Gradle Kotlin DSL
   - Compose app shell
   - baseline CI build task
   - package name `com.vela.android`

2. Extract shared core:
   - Create `libVELA/vela-core`.
   - Move/copy desktop vault models, password generation, domain matching, sync merge, audit serialization, and DTOs.
   - Add unit tests comparing JSON compatibility with desktop models.

3. Add Android Rust bridge:
   - Use UniFFI unless blocked by crate compatibility; fallback to JNI manually.
   - Build Rust static/shared library for Android ABIs.
   - Expose DTO-based methods only, no Android-specific concepts in Rust.

4. Implement local vault:
   - Keystore RMS wrapping.
   - password fallback.
   - encrypted vault save/load.
   - session timeout.
   - CRUD/search/generator screens.

5. Implement AutofillService:
   - manifest/service metadata.
   - structure parser.
   - dataset builder.
   - unlock authentication flow.
   - save/update flow.
   - login/card support first, then TOTP/identity extensions.

6. Implement server mode:
   - settings server URL.
   - register/authenticate.
   - sync manifest/chunks.
   - conflict resolution.
   - background WorkManager sync.

7. Implement full parity screens:
   - devices, sharing, audit, recovery, breach monitor, file blobs.
   - reuse server APIs and shared core logic.

8. Hardening:
   - locked-state leak checks.
   - screenshots disabled on sensitive screens via `FLAG_SECURE`.
   - clipboard clear.
   - backup policy: exclude encrypted RMS/session material; decide whether encrypted vault backup is allowed.

## Tests And Acceptance Criteria

Unit tests:

- Vault model serialization matches desktop JSON.
- Domain matching matches desktop behavior.
- Password generator and strength match desktop behavior.
- Tombstone merge and conflict detection match desktop behavior.
- Sync chunk split/encrypt/decrypt round trips.
- Autofill field classifier handles login, TOTP, card, ambiguous, and ignored fields.

Android instrumentation tests:

- Create local vault without server.
- Unlock with biometric mocked/fallback password.
- Add/edit/delete login while offline.
- Autofill locked vault returns authentication dataset.
- Autofill unlocked vault returns matching dataset.
- SaveRequest creates a new login.
- SaveRequest updates an existing login after confirmation.
- Server unavailable does not block local vault use.
- Sync succeeds against local `serverVELA`.
- Conflict resolution keeps local/server version as selected.

Manual acceptance:

- Android app can be installed and run on emulator/API 26+.
- User can enable VELA as system autofill provider.
- Login autofill works in Chrome/web views and native app login screens.
- Credit card autofill works for standard payment forms.
- App remains usable with airplane mode enabled.
- Full desktop feature set is represented in Android UI.

## Assumptions And Defaults

- Chosen stack: native Kotlin Android.
- Chosen first milestone scope: full desktop parity plus Android autofill.
- Chosen offline model: local-first vault, server optional.
- Minimum Android API: 26, because Android AutofillService was added in API 26.
- UI toolkit: Jetpack Compose.
- Rust bridge: UniFFI preferred.
- Sync compatibility: keep existing server APIs unchanged unless Android exposes a missing endpoint.
- Autofill priority: login and credit card fill/save first; identity autofill can follow once base service is stable.
- Android docs used for API constraints:
  - https://developer.android.com/reference/android/service/autofill/AutofillService
  - https://developer.android.com/reference/android/view/autofill/AutofillManager.html

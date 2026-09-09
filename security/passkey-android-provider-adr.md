# ADR — Android passkey provider

**Status:** Implemented and validated on device — the provider service,
ceremony, vault storage and sync plumbing are in
(`androidVELA/app/.../security/passkey/`, the bridge's `passkey.rs`).
Create and get ceremonies verified live against real relying parties
(webauthn.io, a strict local RP, a native app via Clerk, IronFox) and
desktop ↔ phone sync confirmed both directions; see Consequences.
**Date:** 2026-08-20
**Applies to:** `androidVELA/`, `libVELA/vela-android-bridge/`
**Related:** `security/m7_oneshot_assertion.spthy`,
`desktopVELA/vela-desktop-core/src/passkey.rs`

---

## Context

The desktop and browser extension serve VELA-stored passkeys to websites via
the WebAuthn shim. On Android, VELA only *consumes* platform passkeys for its
own recovery flow (`WebAuthnCeremony.kt`); it does not act as a **passkey
provider** — a credential store a website or app asks to answer a WebAuthn
ceremony, the role Google Smart Lock / Chrome play.

The user asked for passkey **provider** support on Android. This is
implementable (unlike desktop macOS, which has no public passkey-provider API)
via Android's Credential Manager provider framework.

## Goal / non-goals

**Goal:** register the VELA Android app as a passkey provider so that a website
(in Chrome) or an app calling `navigator.credentials.get/create` is offered a
VELA-stored passkey, with the same security guarantees as the desktop core: the
private key is used where it is stored and never leaves the device, one
ceremony per human action, and an assertion is bound to one relying party.

**Non-goals**
- Not a replacement for the existing recovery flow.
- No on-device biometric cheating: user *verification* comes only from a real
  unlock/verification the user performs in VELA's own confirmation UI, mapped to
  the same `PresenceToken`-verified concept as the desktop.
- No change to the desktop/extension story.

## Discovery that shapes the design

- Android already links the Rust core over JNI (`vela-android-bridge` +
  `vela-crypto`, compiled for all four ABIs) — but the Android **vault is
  Kotlin**, not the Rust `AppState` vault.
- `desktopVELA/.../passkey.rs` has the proven ceremony (`make_credential`,
  `get_assertion`) but it is coupled to the Rust vault/session/RMS, so it
  cannot read the Android vault as-is.
- The Android vault (`VaultModels.kt`) has **no passkey item type** — a provider
  can only serve credentials that are on-device.

## Decision

### 1. Provider role — `androidx.credentials.provider.CredentialProviderService`

Implement a bound service extending
`androidx.credentials.provider.CredentialProviderService`, overriding
`onBeginGetCredentialRequest` and `onBeginCreateCredentialRequest`. The platform
invokes these when a website/app asks Credential Manager for a passkey; VELA
answers with a `PendingIntent`-based response so it can first show its own
approval/unlock UI (establishing presence, and **unlocking the vault**, since a
passkey's private key is only usable from an unlocked vault).

Manifest additions (additive — a new `<service>`, no existing component
changes):
- `android:permission="android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE"`
- intent-filters: `androidx.credentials.action.BEGIN_GET_CREDENTIAL` and
  `BEGIN_CREATE_CREDENTIAL`
- `android:exported="true"` (required for a provider), plus the
  `android.credentials.GET_PREFERRED_CREDENTIAL_PROVIDER` / related query
  elements as ruled by the platform.

### 2. On-device passkey storage (prerequisite a provider cannot skip)

Add a `Passkey` item to the Android vault (model + JSON + repository + the
exhaustive `when` switches over `VaultItem`):

```kotlin
data class Passkey(
  override val meta: VaultMeta,
  val rpId: String,
  val rpName: String,
  val credentialId: String,   // base64url
  val userHandle: String,     // base64url
  val userName: String,
  val userDisplayName: String,
  val cosePublicKey: String,  // base64url
  val privateKey: String,     // base64url (scalar), sealed by the encrypted store
  val signCount: Long,
) : VaultItem
```

Sync: add passkeys to the vault sync payload so passkeys created on desktop can
be served on Android and vice-versa. Where the sync endpoint is per-item-typed,
extend it for the new type in the same additive way.

### 3. Ceremony: reuse the Rust crypto primitives, keep storage in Kotlin

Porting the whole `passkey.rs` ceremony to Kotlin duplicates cryptography that
is already audited in Rust, so do not. Instead:

- Extend `vela-android-bridge` to expose **stateless** primitives currently
  inside `passkey.rs` (ES256 keygen, `build_authenticator_data`,
  `build_attestation_object`, signing), so the Kotlin ceremony composes them
  against Kotlin-stored keys — reusing the same crypto the desktop uses without
  copying it.
- The Kotlin `PasskeyAuthenticator` mirrors the desktop invariants: RP ID hash
  inside `authenticatorData`, sign-count persisted after each assertion, user-
  verification only when VELA actually verified the user (presence), and
  one-ceremony-per-approval.

If bridging the primitives proves too invasive for this PR, a fallback is a
self-contained Kotlin implementation isolated in one file and covered by JVM
unit tests; the ADR records the preference for the bridge.

### 4. Presence / user verification

Serve a passkey only after the user sees VELA's confirmation screen and, when
the RP requires it, a real verification (biometric/PIN via the already-requested
`USE_BIOMETRIC`). The Kotlin ceremony sets the `UV` flag in `authenticatorData`
only when that happened — not because the RP requested it.

### 5. Additive / safety

Everything is additive: a new vault item variant, a new service, a new activity,
a new settings affordance to set VELA as the provider. Existing vault items,
autofill, recovery and sync flows are untouched. The exhaustive `when` blocks
over `VaultItem`/`VaultItemType` are extended (a compile-time requirement, which
is what makes adding the variant safe).

## Consequences

- **Positive.** Passkeys follow the user across desktop (shim) and Android
  (Credential Manager provider); the ceremony security invariants are preserved.
- **Accepted.** Requires the APK built by CI (verify-android / release-android)
  and a real device to become the passkey provider and to validate a
  create/get ceremony. The SDK now exists locally for builds and tests, but
  CI remains the only release path: release APKs are signed from the CI
  secret, so the same signature upgrades over any prior install without
  ever wiping the vault.
- **Guard.** A unit test proves the Kotlin ceremony reproduces the desktop's
  `authenticatorData`/`attestationObject`/signature shape (fixed test vectors),
  so the two transports stay behaviorally identical.
- **Discovered during validation: browsers parsing Credential-Manager
  responses demand the extended WebAuthn L3 JSON**, not the spec minimum —
  Chromium's converter cross-checks `publicKeyAlgorithm` against the
  attestation, requires `authenticatorData` byte-identical to the
  attestation's, and requires the SubjectPublicKeyInfo DER `publicKey` for
  ES256. The bridge derives the SPKI DER next to the COSE key (hand-encoded,
  test-pinned to carry the same point), and both response builders emit the
  full shape.
- **Discovered during validation: the passkey provider must honor the same
  privileged-browsers union as autofill.** Chromium-family browsers and
  Mozilla's official builds are on Google's list; forks like IronFox are only
  in the community list, so origin assertions from them failed until
  `resolveOrigin` merged all three shipped lists. A browser on none of them
  is still refused, not downgraded.

### Validated end-to-end

- Vanadium (Chromium via Credential Manager): webauthn.io registration and
  authentication, both ceremonies.
- A strict local relying party (verification independent of the browser):
  challenge bytes, origin, RP ID hash, ES256 signature, and sign count
  verified offline against the registered public key.
- T3 Code (native app via Credential Manager/Clerk): the
  `android:apk-key-hash:<calling-app cert>` origin is accepted by the
  relying party's asset-links policy.
- IronFox (Firefox-family): works once the allowlist union is honored —
  Firefox-family browsers route through Credential Manager and declare the
  site origin themselves.
- Desktop ↔ phone sync: phone-minted passkeys arrive on the desktop with
  their keys; desktop passkeys arrive on the phone and authenticate.
- **Not reachable by any Credential-Manager provider, by upstream browser
  policy: Cromite** (strips the CredMan WebAuthn routing) and any browser
  speaking only the legacy GMS FIDO2 API. `chrome://flags/#web-authentication-cred-man`
  in Cromite is an unsupported workaround, not a supported configuration.

## Open items
- Where the sync payload is type-keyed, confirm server-side handling for the
  new passkey type. — *Resolved by inspection: passkeys ride the same sealed
  vault chunks as every other item; the new `private_key` field deserializes
  on the desktop with a default, and the desktop restores its stored key for
  keyless updates, so a keyless item can never overwrite a live credential.*
- Whether to land the provider service (device-visible but inert until a
  passkey exists + the user sets VELA as provider) in the same PR as storage.
  — *Yes, one additive PR; the service is inert until the user enables it in
  system settings.*
- Signed-out enumeration: when the vault is locked, `onBeginGetCredentialRequest`
  answers with an "Unlock VELA" authentication action rather than entries.
  Entries cannot honestly be listed from a sealed vault; a locked device will
  not be suggested until it has been unlocked once this session.
- Pre-provider passkeys (synced before the key existed on Android) are
  metadata-only until the first sync after upgrade. Android never uploads a
  keyless snapshot over the server's keyed copies: when keyless passkeys
  exist locally it pulls and merges first, and the merge rule itself
  backfills a key from either side (`mergeVaultStores`) — a timestamp race
  can decide names, never whether a credential keeps its key.
  — *Verified live: a pre-provider desktop passkey backfilled its key via
  sync and authenticates from the phone.*
- Browser support matrix. — *Closed: Chromium-family and Mozilla-family
  browsers work (IronFox validated after the allowlist union); Cromite and
  legacy GMS-FIDO2-only browsers are unreachable by upstream policy — see
  Consequences.*

# ADR — Android passkey provider

**Status:** Accepted — in progress (implementation PR builds the APK in CI; the
provider must be validated on a real device by setting it as the passkey /
"preferred authenticator" provider).
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
  create/get ceremony — this box has no Android SDK, so CI is the build and a
  device is the test bed.
- **Guard.** A unit test proves the Kotlin ceremony reproduces the desktop's
  `authenticatorData`/`attestationObject`/signature shape (fixed test vectors),
  so the two transports stay behaviorally identical.

## Open items
- Where the sync payload is type-keyed, confirm server-side handling for the
  new passkey type.
- Whether to land the provider service (device-visible but inert until a
  passkey exists + the user sets VELA as provider) in the same PR as storage.

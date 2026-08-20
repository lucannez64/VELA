# ADR — Native passkey providers for the desktop core

**Status:** Accepted (design only; implementation deferred until a Windows build
environment can compile and validate it).
**Date:** 2026-08-20
**Applies to:** `desktopVELA/vela-desktop-core/src/passkey.rs`
**Related:** `security/formal/m7_oneshot_assertion.spthy`,
`extension/src/content/webauthn-shim.js`.

---

## Context

VELA stores and signs with WebAuthn credentials in the desktop core. Today the
only transport that drives a ceremony is the browser-extension shim
(`webauthn-shim.js`), which overrides `navigator.credentials.get/create` in the
page world and asks the core for signatures. `passkey.rs` is deliberately
transport-agnostic: `make_credential(state, request, PresenceToken)` and
`get_assertion(state, request, PresenceToken)` take plain request/response
structs precisely so that *other* front ends — an OS-provider adapter being the
original intent — can drive the same two functions without touching the
ceremony code.

This ADR splits the "future native macOS/Windows provider APIs" idea into what
is real, what is not, and how a future implementation plugs in.

---

## Decision

### 1. `passkey.rs` stays the single source of truth

Do not fork the ceremony logic per platform. `make_credential` /
`get_assertion` are the only place a credential is created or a private key is
used; every adapter (extension shim today, any native provider tomorrow) maps
its own request envelope onto `MakeCredentialRequest` /
`GetAssertionRequest` and maps the response back. This keeps the M7 guarantee
(`credential_never_leaks`) in one place and makes a native adapter a thin
translation layer, not a second implementation.

The two load-bearing invariants must be preserved by whichever adapter calls
in:

- **One ceremony per human action** — both functions take `PresenceToken` by
  value (not `Clone`, not `Copy`). A native provider must obtain a token from
  `crate::presence` for each platform-initiated ceremony, never mint one
  itself.
- **An assertion is bound to one RP** — the RP ID hash is inside the signed
  `authenticatorData`. The adapter must hand the platform's RP ID through
  unchanged, never rewrite it.

### 2. Windows — the one implementable native target

Windows exposes the **WebAuthn native client API** (`webauthn.dll`). The model
a third-party credential service fits into is the **plugin authenticator**:
Windows (the caller of `WEBAUTHN` APIs in browsers and the OS) consults a
registered plugin authenticator, which supplies `GetAssertion` and
`MakeCredential` callbacks for credentials Windows itself does not hold. VELA's
vault is exactly a "credential store the platform does not hold", so this is
the correct seam.

Concrete mapping (all `#[cfg(target_os = "windows")]`, not yet implemented):

| Windows WebAuthn type | VELA core type |
|---|---|
| `WEBAUTHN_PLUGIN_AUTHENTICATOR` (MakeCredential / GetAssertion callbacks, `ClosedHandle`) | a wrapper whose callbacks call `passkey::make_credential` / `passkey::get_assertion` |
| `WEBAUTHN_RP_ENTITY_INFORMATION` / `WEBAUTHN_USER_ENTITY_INFORMATION` | `rp_id`, `user_handle`, `user_name`, `user_display_name` |
| `challenge` (`WEBAUTHN_CBOR_*` / byte array) | the `client_data_hash` the caller must pre-hash, or VELA builds `clientDataJSON` like the shim |
| `WEBAUTHN_CREDENTIAL_EX` (allow/exclude lists) | `allow_credential_ids` / `excluded_credential_ids` |
| `WEBAUTHN_AUTHENTICATOR_ATTACHMENT` / UV policy | `require_user_verification` |
| success callback verdict + `WEBAUTHN_CREDENTIAL_ATTESTATION` / `WEBAUTHN_ASSERTION` | `MakeCredentialResponse` / `GetAssertionResponse` |
| `WEBAUTHN_CREDENTIAL_DETAILS` (created/updated callbacks) | the `credential_id` / `sign_count` fields on the vault `Passkey` item |

Presence and user verification are the subtle part: Windows reports whether
the authenticator performed user verification in the returned
`WEBAUTHN_CREDENTIAL_ATTESTATION` / `WEBAUTHN_ASSERTION` flags. A future
adapter must route a *verified* result through the same `PresenceToken`
(verified == true) path the shim uses, so `UV` in `authenticatorData` is set
only when a real verification factor was established — not because the caller
said so.

Credential storage stays in the existing `VaultItem::Passkey` vault item. The
adapter is a transport only; it never keeps its own credential tables.

**Deferred-out:** Windows implementation is out of scope for this branch. It
requires a Windows SDK/build (`target_os = "windows"`, `windows-rs` or raw FFI
against `webauthn.dll`) which this Linux environment cannot compile, and the
plugin-authenticator struct layout is ABI-sensitive — shipping it unverified
would be worse than not shipping it. The plan above is the seam to fill.

### 3. macOS — there is no public desktop passkey-provider API

`ASCredentialProviderExtension` is the OS-backed provider API, but it is for
**AutoFill on iOS** (serving a user's stored passwords/passkeys into the OS
AutoFill flow) — it does **not** let a third party answer an arbitrary
website's `navigator.credentials.get()` on desktop macOS, where the platform
uses iCloud Keychain for passkeys. There is therefore **no public macOS desktop
API** a VELA macOS app could use to "be a passkey provider" for websites.

Decision: do **not** build a fake "macOS provider" adapter. On macOS the
supported paths are:

- **iOS AutoFill / recovery** — already implemented in
  `iosVELA/AutoFill`/`WebAuthnCeremony.swift`.
- **Desktop + webpage passkeys** — the extension shim (as today), whose
  remaining `instanceof`-compat gap was closed in the shim fix; the residual is
  only the in-page-wrapper calls an OS provider could avoid, and macOS offers
  no route to that.

If Apple later ships a desktop passkey-provider API, this ADR's "the core is
the single source of truth" position means only a new thin adapter is needed —
no ceremony change.

---

## Consequences

- **Positive.** The design "future native provider" claim is now a concrete,
  scoped plan (Windows plugin authenticator) instead of an aspiration; the
  ceremony functions are confirmed API-stable for any front end; no
  platform-specific logic leaks into the security-relevant core.
- **Accepted.** Windows implementation and validation are blocked on a Windows
  build environment. Desktop-macOS-as-provider is not implementable at all via
  a public API and is explicitly not pursued.
- **Guard.** Any future adapter must come with a test that proves `UV` and the
  one-ceremony-per-token invariants still hold when driven by the Windows
  platform callbacks, mirroring the shim's presence handling.

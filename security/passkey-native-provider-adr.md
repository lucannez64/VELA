# ADR — Native passkey providers for the desktop core

**Status:** Accepted; **Windows implemented** (`desktopVELA/vela-win-passkey`,
shipped 2026-09-08). macOS remains design-only (see §3).
**Date:** 2026-08-20 (Windows section implemented 2026-09-08)
**Applies to:** `desktopVELA/vela-desktop-core/src/passkey.rs`
**Related:** `security/formal/m7_oneshot_assertion.spthy`,
`extension/src/content/webauthn-shim.js`, `desktopVELA/vela-win-passkey/`.

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

### 2. Windows — implemented (vela-win-passkey)

Windows 11 ships the **plugin passkey manager API** (24H2+ with the
2025-11 cumulative update; finalized `*2` APIs in 26100/26200.8524):
`WebAuthNPluginAddAuthenticator` registers a credential manager, the OS then
routes WebAuthn ceremonies it does not hold to the registered COM object.
The implementation lives in `desktopVELA/vela-win-passkey`:

- `vela-passkey-provider.exe` — out-of-proc COM server implementing
  `IPluginAuthenticator` (MakeCredential / GetAssertion / CancelOperation /
  GetLockStatus). Requests arrive as CTAP2 CBOR and are decoded with the
  platform's own `WebAuthNDecode*` helpers; responses are encoded with
  `WebAuthNEncode*`. Every request's `pbRequestSignature` is verified against
  the OS operation-signing key returned at registration (CNG, RSA-PSS or
  ECC) — a forged ceremony from a local process is refused before it ever
  reaches the desktop.
- **Package identity is mandatory** (`0x80073D54` otherwise): `msix/` holds
  a sparse identity package ("packaging with external location") plus the
  fusion manifest embedded into the exe by `build.rs` (binaries only — a
  process carrying an unresolvable identity breaks its own COM lookups).
  `msix/register-dev.ps1` does the dev flow; production installers call the
  equivalent `Add-AppxPackage -Path ... -ExternalLocation ...`.
- Transport: the provider talks to the desktop over the existing per-user
  pipe with the same framed JSON the extension host uses, plus
  `provider_status` / `provider_sync_credentials` (public metadata only).
  The connection gate (`ipc_gate`) admits `vela-passkey-provider.exe` on
  same-user + exe identity — COM launches it, so there is no browser
  ancestry to check. Stated residual, pinned as a gate test: a same-user
  copy of the provider binary passes the gate, and is bounded by the
  presence prompt (which names it as requester), not by the gate.
- One ceremony at a time (`ERROR_BUSY` for a second concurrent request);
  `CancelOperation` discards an in-flight result rather than returning a
  signature for a withdrawn transaction; `GetLockStatus` mirrors the
  desktop's session state (unreachable desktop = locked).
- Credential storage stays in the existing `VaultItem::Passkey` vault item.
  The adapter is a transport only; it never keeps its own credential tables.

The original struct mapping below is superseded by the shipped one: the
platform does not hand the plugin `WEBAUTHN_PLUGIN_AUTHENTICATOR` callbacks;
it hands CTAP2 CBOR buffers over the `IPluginAuthenticator` COM interface.

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

- **Positive.** The design "future native provider" claim is implemented for
  Windows: the ceremony functions were confirmed API-stable, no
  platform-specific logic leaked into the security-relevant core, and the
  Windows adapter is a thin translation layer (decode CBOR → map onto
  `MakeCredentialRequest`/`GetAssertionRequest` → encode). Verified on
  Windows 11 25H2 (build 26200.9168): OS registration accepted, COM
  activation and `GetLockStatus` round-trip, gate admission, and credential
  metadata sync all pass.
- **Accepted.** Desktop-macOS-as-provider is not implementable via a public
  API and is explicitly not pursued.
- **Guard.** The Windows adapter's presence path is unchanged: `UV` in
  `authenticatorData` is whatever the desktop's `presence` gate minted, and
  one ceremony costs one token — enforced by `passkey.rs` taking
  `PresenceToken` by value, not by the adapter.
- **Accepted.** Desktop-macOS-as-provider is not implementable via a public
  API and is explicitly not pursued.
- **Open.** The release pipeline must sign the identity `.msix` once VELA
  has code-signing certificates configured (unsigned packages are refused
  by `Add-AppxPackage` on end-user machines); the workflow already builds
  it and the installers ship it.

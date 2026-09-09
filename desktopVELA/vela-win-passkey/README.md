# vela-win-passkey — VELA as a Windows system-wide passkey provider

Makes VELA answer WebAuthn for **every** browser and app on a Windows machine,
not just pages running the VELA extension. This is the same integration path
1Password and Bitwarden use: the Windows 11 plugin passkey manager API.

```text
[browser / app] --WebAuthn--> [Windows webauthn.dll]
     --CTAP2 CBOR over COM--> [vela-passkey-provider.exe (this crate)]
     --JSON over named pipe--> [vela-desktop-core (vault + presence)]
```

The provider is a transport only: every ceremony is still performed by
`vela-desktop-core::passkey` behind the human-presence gate, so the
`credential_never_leaks` property and the one-ceremony-per-presence-token
invariant hold unchanged (see `security/passkey-native-provider-adr.md`).

## Requirements

- Windows 11 24H2/25H2 with the 2025-11 (or later) cumulative update — the
  build must export the plugin API from `webauthn.dll` (finalized `*2` APIs
  from 26100/26200.8524, KB5089573).
- **Package identity**: the OS refuses `WebAuthNPluginAddAuthenticator` from
  a process without it (`0x80073D54`). This crate grants it via a *sparse
  identity package* (`msix/`) bound to the app's install directory — no full
  MSIX repackaging needed.
- The VELA desktop running (for ceremonies; `GetLockStatus` degrades to
  "locked" without it).

## Development setup (this machine)

```powershell
# 1. Build the provider (build.rs embeds the identity manifest into the exe).
cargo build -p vela-win-passkey

# 2. One-time: create + trust a dev cert, register the identity package.
powershell -File msix\register-dev.ps1          # needs one UAC elevation

# 3. Register VELA with the OS passkey system. Without identity, this
#    bootstraps: registers the identity .msix shipped next to the exe
#    (dev fallbacks included), re-execs with identity, then calls
#    WebAuthNPluginAddAuthenticator.
cargo run -p vela-win-passkey --bin vela-passkey-provider -- --register

# 4. Enable VELA in Settings > Accounts > Passkeys > Advanced options.

# 5. (optional) push existing vault passkeys into the OS autofill cache
cargo run -p vela-win-passkey --bin vela-passkey-provider -- --sync-credentials
```

Other CLI modes: `--status`, `--unregister`, `--whoami` (identity diagnostic),
`-Embedding` (the COM server, normally launched by Windows itself). Any of
them accepts `--json` for a machine-readable verdict — that is what the
desktop's Settings actions parse (the desktop shells out because it does not
carry package identity itself).

## Tests

```text
cargo test -p vela-win-passkey --lib                     # unit tests
cargo test -p vela-win-passkey --lib -- --ignored        # live COM activation
cargo test -p vela-win-passkey --test desktop_ipc -- --ignored   # live pipe e2e
```

The two ignored tests bind real machine state (registered identity package,
free per-user pipe); run them explicitly, with no desktop process running for
the second.

## How it works

- `src/ffi.rs` — hand-verified `#[repr(C)]` mirrors of `webauthnplugin.h` /
  `webauthn.h` plus runtime resolution of every `webauthn.dll` export. The
  layouts are the ABI contract; diff against `microsoft/webauthn` when
  touching.
- `src/com.rs` — the COM server: `IPluginAuthenticator`
  (`d26bcf6f-b54c-43ff-9f06-d5bf148625f7`), class factory,
  `CoRegisterClassObject` + park. One ceremony at a time; `CancelOperation`
  discards in-flight results.
- `src/ceremony.rs` — verify the OS request signature (CNG; RSA-PSS or ECC),
  decode CTAP2 with the platform helpers, map onto the desktop's
  `passkey_create` / `passkey_get` payloads verbatim (RP ID and client-data
  hash are never rewritten), encode the response, push autofill metadata.
- `src/registration.rs` — COM `LocalServer32` key, `authenticatorGetInfo`
  CBOR (ES256 only, zero AAGUID, no extensions — exactly what VELA is),
  autofill cache push/clear.
- `src/desktop.rs` — pipe client, sharing `vela-nm-host`'s transport.
- `msix/` — identity package manifest, fusion manifest (also embedded into
  the exe by `build.rs`), logos, and the dev registration script.

## Packaging

- `src-gpui/Cargo.toml` (`[package.metadata.packager]`) ships
  `passkey-provider/{vela-passkey-provider.exe, VELA.PasskeyProvider.msix,
  Assets/}` in both the NSIS setup and the WiX MSI — no installer hooks
  needed (cargo-packager 0.11.8 has none): the provider exe bootstraps its
  own identity package on first `--register`.
- `.github/workflows/release-desktop.yml` builds the provider exe and the
  identity package with MakeAppx. **The .msix must be signed by a
  certificate target machines trust** (`CERT_E_UNTRUSTEDROOT` otherwise);
  wire the release signing step once VELA has code signing configured.
- Uninstalling: the NSIS setup deletes the files; the OS-side registration
  is removed by the Settings "Disable" action or
  `vela-passkey-provider.exe --unregister`.

## Desktop-side seams

- `vela-desktop-core/src/ipc_gate.rs` — admits `vela-passkey-provider.exe`
  (same user, exe identity; no browser ancestry exists for a COM launch).
  Residual, pinned by test: a same-user copy of the binary passes the gate
  and is bounded by the presence prompt, not the gate.
- `vela-desktop-core/src/ipc.rs` — `provider_status` (lock state for
  `GetLockStatus`) and `provider_sync_credentials` (vault-wide passkey
  metadata for the OS autofill cache; provider-only endpoint, re-checked
  per message). Passkey ceremonies created via the extension now also push
  autofill metadata.
- `vela-desktop-core/src/commands/provider.rs` — toolkit-agnostic
  register/unregister/status/sync for both front ends (gpui Settings section;
  Tauri commands `passkey_provider_*`).

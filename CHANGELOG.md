# Changelog

All notable changes to VELA are documented in this file. Versions are
workspace-wide; individual components (extension, desktop bundles) carry their
own build numbers where noted.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Ephemeral web access: QR-linked, time-boxed, revocable browser sessions in
  **Read-Only** (one-shot sealed vault snapshot, RMS never enters the browser)
  and **Read-Write** (per-chunk keys sealed to an ephemeral hybrid keypair,
  live sync, `kind=web_ephemeral` device) modes.
  Design: `EPHEMERAL_WEB_ACCESS_DESIGN.md`.
- Passkey support in the browser extension: `navigator.credentials` shim that
  relays WebAuthn create/get ceremonies to the desktop core over native
  messaging. The credential private key never leaves the desktop core.
- Server-side WebAuthn/FIDO2 recovery credential registration and assertion
  (`/recovery/webauthn/register/*`, `/recovery/initiate`, `/recovery/recover`).
- RMS-possession recovery path (M18): a challenge-bound proof of possessing
  any two Shamir shares, usable without WebAuthn or Share 2 release
  (`/recovery/initiate-proof`, `/recovery/recover/proof`).
- Two-phase, idempotent recovery-share publication with an encrypted
  client-side journal (desktop: fsynced vault-encrypted file; Android:
  Keystore-backed preferences; Apple: device-only Keychain item). Same-epoch
  share-mixing is impossible; the first finalized split locks the epoch.
- Server-blind vault rekeying state machine
  (`/vault/rekey/start|capsules|commit|abort`): single-seed rotation retires
  every derived key at once; epoch travels in AEAD associated data; commits
  are replay-safe via `X-Vela-Epoch` idempotency; lazy 15-minute timeout
  rollback with no cron.
- Path ORAM vault sync with a **trivial-ORAM fast path** for small vaults
  (≤ 4 chunks); both modes proven observationally equivalent for access-pattern
  hiding (ProVerif, `security/formal/`).
- Trusted-contact recovery channel (M18): recipient-bound, context-bound
  Share-3 envelopes; re-sealed to the requester's ephemeral key on recovery —
  raw share text never travels.
- Server: native TLS (`TLS_LISTEN_ADDR`) and HTTP/3 support; systemd/reverse
  proxy deployment guide (`serverVELA/DEPLOY_SYSTEMD.md`); encrypted migration
  bundles (`cargo run -- migrate export|import`).
- Native gpui desktop front end (Linux) alongside the Tauri + React front end,
  sharing the headless `vela-desktop-core` backend.
- Android autofill hardening: browser allowlist, AssetLinks/pinned-signature
  verification of the calling browser, unlock tokens; release builds refuse
  debug signing unless explicitly overridden.
- Desktop autofill approval doctrine: biometrics prove *presence*, not
  identity; on machines without a biometric factor, an explicit dialog naming
  the specific origin/action satisfies user verification. Approvals are scoped
  per site.
- `security/` tooling: semgrep JS rules, dependency-free Rust scanner
  (`scan.py`), `cargo audit`/`cargo deny` umbrella (`run-scan.sh`), 15 ProVerif
  proof suites (some hax-extracted from the Rust source), ZAP DAST setup, and
  a Python exploit/regression suite proving audit fixes stay fixed.
- CI: desktop release (deb/rpm/msi/nsis), Android release APK, iOS app,
  Firefox XPI signing, fuzzing, security scans, shared compilation cache.

### Changed
- Browser-extension IPC is OS-authenticated only (Windows named pipes / Unix
  sockets); the desktop admits only VELA native-messaging host processes
  spawned by a real browser (kernel-verified process ancestry). There is no
  bearer capability file to steal.
- Server defaults to loopback (`127.0.0.1:8443`); production validation
  rejects wildcard CORS, non-loopback binds without trusted-proxy config or
  `ALLOW_INSECURE_LAN=true`, and plaintext WebAuthn relying-party origins.
- Android blocks cleartext traffic globally except scoped local development
  hosts (`network_security_config.xml`).
- If `PASETO_SECRET_KEY` is unset, the server generates and persists an
  Ed25519 keypair at `{DATA_DIR}/paseto.key` (0600) so sessions survive
  restarts with no manual step.
- Build: shared Cargo target dir, `lld` linker on Linux, `line-tables-only`
  dev debuginfo (≈ −69% target-dir size). See `docs/BUILD_PERFORMANCE.md`.

### Fixed
- Silent `TypeError` when assembling the shimmed WebAuthn credential;
  an explicit dialog approval now correctly satisfies passkey user
  verification.
- CI security workflow collapsed-newline run block; collapsed newline in
  security.yml; artifact paths for the shared target dir (iOS/Android bridge
  builds); RPM asset path for the shared target dir.
- Server and core compiler warnings cleaned up.

### Security (audit remediations)
- S-1/S-4: ephemeral web-session grants are account-bound before the QR code
  is displayed; poll-secret binding closes the QR-token race; grant-hijack
  and enrollment-hijack regressions are covered by
  `security/exploits/test_s1_grant_hijack.py` and `test_p1_enrollment_hijack.py`.
- C-1: hybrid identity key material crosses FFI only as an opaque
  `IdentityHandle`, never as a string.
- D-3: desktop biometric capability reporting is honest — Windows Hello /
  Touch ID are never claimed when the underlying hardware factor is absent.

## [0.1.0] — initial private development release

- Hybrid post-quantum protocol v2.0: ML-DSA-87 + Ed25519 device identity,
  ML-KEM-1024 + X25519 key encapsulation, XChaCha20-Poly1305 vault chunks,
  BLAKE3 domain-separated KDF from a 32-byte Root Master Seed. See `SPEC.md`.
- Clients: desktop (Tauri + React, gpui), Android (Kotlin, minSdk 26),
  iOS (SwiftUI, iOS 16+), browser extension (MV3, Chromium + Firefox),
  ephemeral web vault (WASM SPA served same-origin by the server).
- Server: Rust/Axum, embedded sled + stoolap storage (single binary, no
  PostgreSQL/Redis), PASETO v4 sessions, sled-backed rate limiting and
  revocation.
- Zero-knowledge properties: passwordless server identity, fixed-size padded
  opaque blobs, Path ORAM access-pattern hiding, end-to-end encrypted audit
  log.

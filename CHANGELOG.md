# Changelog

All notable changes to VELA are documented in this file. Versions are
workspace-wide; individual components (extension, desktop bundles) carry their
own build numbers where noted.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Migration importer fidelity: Bitwarden JSON and 1Password `.1pux` now bring
  cards, identities, custom fields, extra websites and favorites alongside
  logins and notes. Folder paths and tags become first-class collections when
  the vault is upgraded, and are otherwise folded into notes rather than lost.
  `.1pux` archives are read directly (ZIP + `export.data`). The import report
  now carries the detected source, preserved/converted counts and field-level
  unsupported losses. See `docs/IMPORT_FIDELITY.md`.
- Shared organization/rich-item schema foundation (`vela-core::rich_items`):
  folder and tag operations, deterministic merge and permanent organization
  tombstones; custom fields, additional URL records and identity/address types;
  validation, secret redaction and forward-compatible record fixtures. These
  types now round-trip through vault sync and encrypted archives. Desktop
  collections sit in the existing sidebar with direct create/edit forms,
  folder-scoped counts and contextual bulk actions. New items inherit the
  selected folder/tag; bulk tag edits preserve untouched mixed values. Rich
  editors use the app’s rounded controls and Material icons.
  Activation runs on the network runtime and keeps server errors visible.
  Enabling saves an encrypted safety copy and enables the server write-version
  gate; browser access and iOS stay read-only during their UI rollout.
- Android collection management and rich-item editing: nested folders, tags,
  custom fields, additional URLs and identity details are editable in the
  Instrument editor, the vault list filters by folder (with subfolders) or tag,
  and deleting a collection keeps its items. Schema-2 vaults are writable on
  Android, with validation and merge handled by the shared Rust core.
- One-off share links to recipients who do not use VELA (`/send`, `webVELA`
  `send.html`). The sender seals a login or secure note under a random 256-bit
  link key (`vela-crypto::link`) and hands out `…/send.html?id=<id>#<key>`; the
  key lives in the URL fragment, so the server stores only ciphertext it cannot
  open. Optional Argon2id passphrase, expiry (5 min–30 days), max-views, and
  view-once are enforced server-side, and every fetch is one indistinguishable
  `404` when the link is gone. The recipient page decrypts in the browser via
  the WASM bridge. New UI in both desktop front ends (Tauri/React Sharing →
  Links, and gpui); the owner's link records — including the key — are kept in
  an encrypted local file so the URL can be re-copied.
- Browser-extension authenticator autofill and popup password generator.
  After a VELA-initiated login fill, the extension fills the one-time code on
  the site's second step automatically: the desktop releases a fresh code
  (never the standing secret), scoped to the login's own domain, with an audit
  entry per release (`TotpCode` IPC type, `vela-nm-host` `getTotpCode`). The
  popup shows a live code with countdown and copy. The popup also gains a
  password generator — random or Diceware passphrase over the bundled EFF word
  list, with look-alike exclusion, a strength estimate, session history, and
  persisted options. Desktop TOTP now honors the otpauth `algorithm` parameter
  (SHA-1/256/512) instead of assuming SHA-1.
- Browser-extension per-site autofill settings and lookalike warning. The
  popup gains a "This site" panel (auto-fill on page load, never autofill,
  never save) stored in `storage.local` and applied by the content script.
  Opt-in auto-fill on page load fills the single unambiguous match and never
  fires on a lookalike domain. A shared IDN/homograph detector decodes
  punycode labels (RFC 3492) and warns when a host mixes writing systems, in
  both the inline dropdown and the popup; single-script internationalized
  domains are left alone. The dead `generateDomainMatchPatterns` helper (wrong
  for multi-label suffixes, never called) is removed.
- Credit-card autofill (fill-only). The browser extension detects card number,
  expiry (combined or split month + year), CVV and cardholder fields and offers
  stored cards after an explicit click on a payment field; the desktop keys the
  release to the page (per-unlock cap + activity-log entry) rather than to the
  card. Android's `AutofillService` fills the same payment group, including the
  unlock-then-fill flow. iOS 18+'s AutoFill extension declares
  `ProvidesTextToInsert` and offers each card value (number, expiry, CVV,
  cardholder) as an individually insertable text, since a credential-provider
  extension cannot return a credit-card credential.
- Instant cross-device sync: a local save is pushed immediately, and an
  authenticated `GET /vault/events` SSE stream tells open clients when another
  device wrote. Events are content-free (writer device, epoch, revision,
  coarse kind; never a chunk id or ciphertext), a subscriber that falls behind
  is told to resync, and a missed event only delays the next scheduled sync.
  Wired into the native desktop app (gpui and Tauri), Android and iOS while
  foregrounded, and the read-write ephemeral web vault.
- Android is a system-wide passkey provider (Android 14+, Credential Manager):
  VELA answers `navigator.credentials` ceremonies from any browser or app with
  VELA-stored passkeys. The private key is used where it is stored (native
  bridge, one signature at a time), every ceremony runs behind VELA's prompt
  screen (unlock, confirm, real biometric/PIN step when the site requires
  verification), and `UV` is set only when that verification actually
  happened. Passkeys now carry their key through sync in both directions, so
  desktop-created passkeys work on Android and vice-versa; the merge never
  strips a key a device already holds, and the phone pulls before pushing
  when its passkey copies predate the provider (key backfill).
  Design: `security/passkey-android-provider-adr.md`.
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
- Security disclosure policy: root `SECURITY.md` (scope, reporting,
  safe harbor, response targets) and a machine-readable
  `.well-known/security.txt` pointing at GitHub private vulnerability
  reporting.

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
- Android uses the Instrument interface throughout: overview, vault, item
  detail, generator, More, Settings, lock, the autofill suggestion cards and
  the passkey approval sheet, built from the shared button/field/card
  primitives. The overview greets by time of day, shows sync state beside the
  wordmark, counts accounts with weak or reused passwords, and lists recently
  opened items; navigation is the floating icon dock from the mobile
  reference. Night, Paper, Catppuccin Macchiato/Latte and Gruvbox follow the
  same palette tokens as desktop, and the active palette now supplies the
  default text colour so unstyled text stays legible. Android-only settings
  (autofill provider, trusted browsers, passkey provider, sync, recovery,
  devices) remain in place. See `docs/ANDROID_INSTRUMENT_IMPLEMENTATION.md`.
- If `PASETO_SECRET_KEY` is unset, the server generates and persists an
  Ed25519 keypair at `{DATA_DIR}/paseto.key` (0600) so sessions survive
  restarts with no manual step.
- Build: shared Cargo target dir, `lld` linker on Linux, `line-tables-only`
  dev debuginfo (≈ −69% target-dir size). See `docs/BUILD_PERFORMANCE.md`.

### Fixed
- Desktop Settings no longer reports the browser extension as "not found"
  while it is installed and working. The extension's native-messaging host is
  started per request, so "connected" is now remembered for the app session
  instead of being cleared when the one-message connection closes; both
  front ends also refresh the indicator while Settings is open.
- GPUI settings use persistent category navigation instead of one long list.
  Cards and action columns share consistent widths, narrow rows stack controls
  below their labels, and interval choices reserve their full wrapped height.
- GPUI dialogs now open above the full app body with pinned headers and action
  buttons; only their content scrolls. Fixes clipped enrollment QR codes and
  inaccessible controls in short windows. A native input-widget fix prevents
  scrolled-out text fields from intercepting clicks on Close or footer actions.
- Sharing now separates searchable item selection from recipient/link options,
  virtualizes large item lists, supports keyboard selection, and shows a compact
  selected-item summary with a Change action. Link creation has a clear ready
  state and inline copy feedback. Enrollment keeps Close/Copy accessible in all
  stages and offers the manual code as an optional fallback.
- GPUI device cards retain their content height instead of shrinking into
  overlapping text in short windows. Device names and actions use the space
  available beside navigation, and long names wrap within their cards.
- GPUI password reveal buttons have a separate fixed-width area in unlock,
  setup, and device import. Long passwords scroll inside the input and
  cannot paint underneath the eye button.
- GPUI vault scrolling uses one virtualized page for search, filters, item
  rows, and health cards. Removes the nested 600px item scroller that made
  wheel input alternate between the page and item list in small windows.
- Desktop layout at narrow widths and short window heights in both GPUI and
  Tauri: navigation remains scrollable, item editors fit their available
  space, and save/cancel controls stay reachable. GPUI stacks the vault
  dashboard and wraps filters on narrow windows; long item names and values
  no longer compete with their action buttons. Settings theme choices and
  sharing dialogs also adapt to smaller windows.
- Desktop item actions remain visible without hover. The Tauri editor now
  focuses its first field, contains keyboard focus, supports Escape, and
  shows a pending save state that prevents duplicate submissions. Adding an
  item from its sidebar creates a new item even while viewing an existing
  one; closing an editor preserves the detail view and saving refreshes it.
- gpui modal backdrops now `occlude()`. gpui decides what handles a scroll
  wheel with `HitboxId::should_handle_scroll`, a hit-box check rather than a
  hover check, so a backdrop's click handler alone did not stop it — the list
  behind an open modal (Add New Item, delete / revoke / share / security-key /
  recovery, etc.) still scrolled under the wheel. Stopping the hit-test at the
  backdrop fixes every modal at once.
- The gpui Activity Log is now virtualized (gpui's variable-height `list`,
  like the vault browser): it builds only the visible rows, flattens the
  day groups once when the log loads, and stops the loading spinner's repaint
  loop once the entries land. A large audit log previously rebuilt every row
  and every hover animation on each repaint — including the 10fps spinner tick
  — which made the app crawl.
- Android passkey creation now performs user verification for
  `userVerification: "preferred"` (WebAuthn's default) as well as `"required"`,
  matching Android platform passkeys. Presence-only creation produced a `UV=0`
  credential that relying parties such as Uber reject at their server even
  though VELA stored the key. Also emits `authenticatorAttachment` and the
  requested `credProps.rk`, and accepts `{"publicKey": …}`-wrapped or
  stringified request JSON.
- Bumped `rustls` to 0.23.45 in `serverVELA` and `desktopVELA`
  (RUSTSEC-2026-0285, TLS 1.3 handshake encryption-level boundary), clearing
  the `cargo-audit` hard gate. The remaining audit notices (`fxhash`,
  `instant`, `proc-macro-error2`) are unmaintained warnings pulled in by `sled`
  and do not fail the gate.
- Android passkey creation now honors user verification. The creation
  dictionary nests `userVerification` under `authenticatorSelection`, but the
  provider read it at the top level, so every relying party that required UV
  (Uber, most banks) got a credential with the `UV` flag clear and rejected the
  registration — even though VELA had already stored the passkey. The prompt now
  runs biometric/device-credential verification and sets `UV` when required.
- Secure notes can now be copied: the desktop vault-list row copy icon takes
  a note's body instead of toasting "Nothing to copy", and every front end
  (gpui, Tauri, Android, iOS) has a copy button on the note detail view.
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

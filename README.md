# VELA

VELA is a local-first, zero-knowledge password vault with:

- `desktopVELA`: Tauri desktop app and browser-extension IPC host.
- `androidVELA`: native Android app.
- `serverVELA`: sync/auth API server.
- `extension`: browser extension and native messaging host.
- `libVELA`: shared Rust crypto and Android bridge libraries.

The app is designed so vault data and root secrets stay on client devices. The server stores encrypted blobs and verifies device authentication, but it must not receive vault plaintext, RMS material, identity private keys, or browser extension secrets.

## Security Model

Important defaults after the hardening pass:

- Desktop browser IPC uses OS-protected IPC only: Windows named pipes or Unix sockets.
- Desktop IPC requires a random per-session capability token.
- Browser extension access is routed through authenticated native messaging, not localhost HTTP.
- Autofill secrets require an active desktop session plus biometric/user approval.
- Server defaults to loopback: `127.0.0.1:8443`.
- Android blocks cleartext globally except scoped local development hosts listed in `network_security_config.xml`.
- Production server startup fails if `PASETO_SECRET_KEY` is missing.
- Production rejects wildcard CORS and enforces HTTPS for auth/recovery endpoints unless `ALLOW_INSECURE_LAN=true`.

## Repository Layout

```text
androidVELA/                 Android application
desktopVELA/                 Tauri desktop application
extension/                   Browser extension and native messaging host
libVELA/vela-crypto/         Shared Rust crypto library
libVELA/vela-android-bridge/ Android JNI bridge
serverVELA/                  Axum sync/auth server
```

## Server

Run from `serverVELA`.

```powershell
cd E:\Projects\VELA\serverVELA
cargo run
```

By default the server binds only to loopback:

```text
127.0.0.1:8443
```

That is correct for local desktop-only testing, but it is not reachable from Android or other LAN devices.

### LAN Development

For Android or another LAN client, bind to all interfaces or the machine LAN IP:

```powershell
cd E:\Projects\VELA\serverVELA
$env:LISTEN_ADDR="0.0.0.0:8443"
cargo run
```

Then test from the server machine:

```powershell
Invoke-WebRequest http://192.168.1.33:8443/health
Test-NetConnection 192.168.1.33 -Port 8443
```

If `Test-NetConnection` fails while the server is running, Windows Firewall is likely blocking inbound port `8443`.

For local LAN HTTP, set clients to:

```text
http://192.168.1.33:8443
```

### HTTPS

The Rust server currently serves plain HTTP. Do not point a client at `https://192.168.1.33:8443` unless a TLS terminator is actually running there.

For HTTPS, put Caddy, nginx, Traefik, or another reverse proxy in front of the server and point clients at the proxy origin.

In production, set:

```powershell
$env:VELA_PRODUCTION="true"
$env:PASETO_SECRET_KEY="<base64-64-byte-ed25519-keypair>"
$env:LISTEN_ADDR="127.0.0.1:8443"
$env:WEBAUTHN_RP_ORIGIN="https://your-domain.example"
$env:CORS_ORIGINS="https://your-domain.example"
```

Terminate TLS in front of the server and forward the standard proxy headers, especially `X-Forwarded-Proto: https`.

### LAN Production Exception

For trusted LAN-only testing without HTTPS:

```powershell
$env:ALLOW_INSECURE_LAN="true"
$env:LISTEN_ADDR="0.0.0.0:8443"
$env:CORS_ORIGINS="http://192.168.1.33:1420,http://192.168.1.31"
```

Do not use `ALLOW_INSECURE_LAN=true` for internet-facing deployments.

## Desktop App

Run from `desktopVELA`.

```powershell
cd E:\Projects\VELA\desktopVELA
bun install
bun tauri dev
```

Build installers:

```powershell
bun tauri build
```

Outputs:

```text
desktopVELA/src-tauri/target/release/bundle/msi/
desktopVELA/src-tauri/target/release/bundle/nsis/
```

### Desktop Dependency Pins

The desktop app currently pins:

- Rust `tauri = 2.11.0`
- JS `@tauri-apps/api = 2.11.0`
- JS `@tauri-apps/cli = 2.11.0`
- `tailwindcss = 3.4.19`

Do not upgrade Tailwind to v4 without migrating the config and PostCSS setup. Tailwind v4 builds but drops the app's custom v3 theme utilities such as `bg-surface`, `text-on-surface`, and `font-body`.

If the packaged app has no styling, fonts, or Material Symbols icons, check that the built CSS contains these rules:

```powershell
Select-String -Path dist\assets\*.css -Pattern "\.bg-surface|\.text-on-surface|\.font-body|material-symbols-outlined"
```

### Desktop Server URL

For LAN development, configure the desktop server URL as:

```text
http://192.168.1.33:8443
```

If you see:

```text
Server authentication failed: Failed to get challenge: error sending request
```

check:

```powershell
Test-NetConnection 192.168.1.33 -Port 8443
Invoke-WebRequest http://192.168.1.33:8443/health
```

Common causes:

- Server is still bound to `127.0.0.1:8443`.
- Server is not running.
- Windows Firewall blocks inbound `8443`.
- Client uses `https://` while the server is serving plain HTTP.

## Android App

Run/build from `androidVELA`.

```powershell
cd E:\Projects\VELA\androidVELA
gradle :app:assembleDebug
```

### Android HTTP vs HTTPS

Android blocks cleartext HTTP by default. The app keeps global cleartext disabled and allows only scoped local development hosts in:

```text
androidVELA/app/src/main/res/xml/network_security_config.xml
```

Currently allowed local cleartext hosts include:

```text
localhost
10.0.2.2
192.168.1.33
vela.local
```

Use this Android server URL for LAN HTTP:

```text
http://192.168.1.33:8443
```

If Android reports:

```text
Cleartext HTTP traffic to 192.168.1.33 not permitted
```

then the IP is missing from `network_security_config.xml`, or the installed APK was built before the exception was added.

If Android reports a failed HTTPS connection to `192.168.1.33:8443`, the usual cause is that no TLS server is listening there. Use HTTP for LAN development, or run a TLS reverse proxy and use its HTTPS URL.

## Browser Extension

The extension no longer talks to the desktop app over localhost HTTP. It uses browser native messaging only.

Build:

```powershell
cd E:\Projects\VELA\extension
bun install
bun run build
```

Register native messaging for Chromium browsers:

```powershell
$env:VELA_CHROME_EXTENSION_ID="<your-audited-extension-id>"
.\native-messaging\register-host.bat
```

The registered Chromium host name is `com.vela.desktop`. Chrome rejects native
messaging host names with hyphens, so stale `vela-desktop` registrations should
not be used.

For Firefox-family browsers, the host is scoped by extension ID through `allowed_extensions`.

The Chromium native messaging host manifest must use a concrete origin:

```text
chrome-extension://<extension-id>/
```

Wildcard origins such as `chrome-extension://*` are intentionally not allowed.

## Crypto Library

Shared crypto is in `libVELA/vela-crypto`.

Current production vault encryption dependencies:

- `chacha20poly1305 = 0.10.1`
- `ml-kem = 0.3.0`

Review notes live in:

```text
libVELA/vela-crypto/SECURITY.md
```

Run tests:

```powershell
cd E:\Projects\VELA\libVELA\vela-crypto
cargo test
```

## Verification Commands

Useful full-stack checks:

```powershell
# Server
cd E:\Projects\VELA\serverVELA
cargo check
cargo audit

# Desktop Rust
cd E:\Projects\VELA\desktopVELA\src-tauri
cargo check
cargo audit

# Desktop frontend and bundle
cd E:\Projects\VELA\desktopVELA
bun audit
bun run build
bun tauri build

# Android
cd E:\Projects\VELA\androidVELA
gradle :app:assembleDebug

# Extension
cd E:\Projects\VELA\extension
bun audit
bun run build

# Crypto
cd E:\Projects\VELA\libVELA\vela-crypto
cargo test
cargo audit

# Android bridge
cd E:\Projects\VELA\libVELA\vela-android-bridge
cargo check
cargo audit
```

## Troubleshooting

### Port 8443 Refused

Check what address the server is listening on:

```powershell
Get-NetTCPConnection -LocalPort 8443 | Select-Object LocalAddress,LocalPort,State,OwningProcess
```

If it shows only:

```text
127.0.0.1  8443  Listen
```

LAN clients cannot connect. Restart the server with:

```powershell
$env:LISTEN_ADDR="0.0.0.0:8443"
cargo run
```

### HTTPS Fails on LAN

The server is plain HTTP unless a reverse proxy terminates TLS. Use:

```text
http://192.168.1.33:8443
```

or put TLS in front and use the proxy URL.

### Android Cleartext Blocked

Add the exact LAN host to:

```text
androidVELA/app/src/main/res/xml/network_security_config.xml
```

Then rebuild and reinstall the APK.

### Desktop Build Has No CSS or Icons

Keep Tailwind on `3.4.19` unless the config is migrated to v4.

Check the built CSS:

```powershell
Select-String -Path dist\assets\*.css -Pattern "\.bg-surface|\.text-on-surface|\.font-body|material-symbols-outlined"
```

If those classes are missing, the Tailwind pipeline is wrong.

### Tauri Version Mismatch

Keep Rust and JS Tauri packages on the same major/minor line:

```text
tauri = 2.11.0
@tauri-apps/api = 2.11.0
@tauri-apps/cli = 2.11.0
```

`tauri-build` is different: `2.6.0` is the currently published build crate and is expected.

### Native Messaging Does Not Connect

Check:

- Desktop app is running.
- Browser native messaging host is registered.
- Chromium registration used `VELA_CHROME_EXTENSION_ID`.
- The native host can read the desktop `ipc_auth.json`.
- The desktop session is active and biometric approval succeeds before secrets are returned.

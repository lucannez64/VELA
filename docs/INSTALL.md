# Installing & First Run

Per-platform setup guides for VELA. Read [the README](../README.md) for the
security model first — VELA is local-first and zero-knowledge, so the server
you point clients at is *yours*.

> **Status:** everything below is self-hosted and sideloaded. There are no
> store listings yet.

---

## 1. The server (required)

Every client syncs against a VELA server. The server stores only encrypted
blobs and can never read your vault.

### Option A — Docker (recommended)

```sh
git clone <this repo> && cd VELA
docker build -t vela-server .
docker run -d --name vela-server \
  -p 8443:8443 \
  -v vela-data:/data \
  -e DATA_DIR=/data \
  vela-server
```

The image bakes in the web vault SPA (ephemeral web access works out of the
box) and runs as a non-root user.

### Option B — from source

```sh
cargo build --release -p vela-server
./target/release/vela-server
```

The server listens on `127.0.0.1:8443` by default. Copy
`serverVELA/.env.example` and configure:

| Variable | Purpose |
| :--- | :--- |
| `DATA_DIR` | Where the DB, sled state, and `paseto.key` live (default `./data`) |
| `LISTEN_ADDR` | Default `127.0.0.1:8443` — loopback by design |
| `PASETO_SECRET_KEY` | Base64 Ed25519 keypair. **Unset ⇒ auto-generated and persisted** at `$DATA_DIR/paseto.key` (0600) |
| `TLS_LISTEN_ADDR` / `TLS_CERT_PATH` / `TLS_KEY_PATH` | Native TLS; otherwise put a reverse proxy (Caddy/nginx/Cloudflare Tunnel) in front — see `serverVELA/DEPLOY_SYSTEMD.md` |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGIN` | Relying party for recovery passkeys — must match how clients reach the server |
| `WEB_DIR` | Serve the web vault SPA same-origin (Docker sets this) |
| `ALLOW_INSECURE_LAN` | Escape hatch for LAN testing; production refuses insecure combos regardless |

**Production validation:** the server refuses to start with wildcard CORS,
non-loopback binds without trusted-proxy config, or plaintext WebAuthn origins
unless you explicitly opt out. This is intentional.

### First run

1. Open `https://your-server:8443` — you should see the web vault landing
   page (it only offers *ephemeral* access; creating an account happens in an
   app).
2. Proceed to **Desktop** (recommended first device) or **Mobile** below.

---

## 2. Desktop (Linux / macOS / Windows)

The desktop app is the hub: it owns enrollment, sync, the browser-extension
bridge, and passkeys.

### Install

**From a release bundle** — grab the artifact from CI
(`release-desktop.yml`): `.deb` / `.rpm` (Linux), `.msi` / NSIS `.exe`
(Windows), macOS bundle.

**From source:**

```sh
cd desktopVELA
bun install
bun tauri build     # or: bun tauri dev
```

A second, Linux-native front end exists (`src-gpui/`, built with
`cargo build -p vela-desktop-gpui`); both front ends share the same core.

### First run

1. Launch VELA. **Create account** on this first device: it generates your
   32-byte Root Master Seed (RMS) locally and registers as the *genesis
   device*. The RMS is wrapped by Windows Hello / Touch ID via the TPM /
   Secure Enclave where available, or by a local device password on machines
   without biometric hardware (this password never leaves the device and is
   never used for server auth).
2. **Set up recovery now** (Account → Recovery). VELA splits the RMS 2-of-3:
   Share 1 → your cloud provider (iCloud/Google Drive), Share 2 → the server
   as ciphertext gated by a recovery **passkey**, Share 3 → a trusted
   contact's device. Two of the three recover your account. Skipping this
   means all device loss = vault loss.
3. Point the app at your server URL when prompted.

### Browser extension + native messaging (autofill & passkeys)

The extension never sees your RMS — it asks the desktop app over
OS-protected IPC, and the desktop only admits host processes actually spawned
by a browser (no tokens to steal).

```sh
cd desktopVELA && cargo build --release -p vela-nm-host
cd ../extension && bun install && bun run build   # dist/chrome and dist/firefox
# Register the native messaging host (pick your browser's script):
extension/native-messaging/register-host.sh          # Chromium-family
extension/native-messaging/register-firefox-host.sh  # Firefox-family
```

- Chromium registration needs your extension ID in `VELA_CHROME_EXTENSION_ID`.
- Load the extension: Chromium → *Load unpacked* `extension/dist/chrome`
  (developer mode); Firefox-family → open `extension/dist/vela-firefox.xpi`
  (permanent installs need AMO signing: `bun run sign:firefox`).
- See `extension/native-messaging/README.md` for per-browser paths, Flatpak/
  Snap browser workarounds, and a ping test for the IPC gate.

Autofill and passkeys then require an active desktop session plus biometric
touch or an explicit approval dialog naming the site being served.

---

## 3. Android

minSdk 26 (Android 8+), targetSdk 35. Biometric unlock uses
`BiometricPrompt` with a `CryptoObject`; the RMS is sealed under StrongBox /
Keystore where available.

**From CI:** the signed release APK from `release-android.yml`.

**From source:**

```sh
cd androidVELA
./gradlew :app:assembleDebug          # development
./gradlew :app:assembleRelease \
  -PvelaKeystoreFile=/path/keystore.jks \
  -PvelaKeystorePassword=...          # release refuses debug-signed output
```

The Gradle build invokes Cargo to build the JNI bridge per ABI — have the
Rust Android targets installed (`cargo ndk`).

**First run:** install the APK → create or scan-enroll an account → enroll
biometrics → the system **Autofill service** (`Settings → Passwords &
accounts → Autofill service → VELA`) fills logins after biometric approval.
Cleartext traffic is blocked system-wide by the app's network policy.

## 4. iOS

iOS 16+, SwiftUI, with a `VELAAutoFill` credential-provider extension.

**From source** (XcodeGen project):

```sh
bash libVELA/vela-apple-bridge/build-xcframework.sh   # VelaCore.xcframework
brew install xcodegen && cd iosVELA && xcodegen generate
xcodebuild -project VELA.xcodeproj -scheme VELA -destination 'generic/platform=iOS'
```

CI recipes: `.github/workflows/ios-app.yml`. `CODE_SIGNING_ALLOWED: NO` is a
CI convenience only — ship builds must be signed.

**First run:** create/enroll → Face ID unlocks the Secure Enclave key, which
unwraps the RMS → enable the credential provider
(`Settings → Passwords → Password Options → Autofill From → VELA`).
Recovery Share 1 backs up via iCloud key-value storage automatically.

## 5. Ephemeral web access (borrowed machines)

No install. On a borrowed laptop, open `https://your-server` in a plain
browser, enter your account ID, and scan the QR (or paste the code) with an
enrolled device. The approving device picks:

- **Read-Only** (default): a one-shot sealed snapshot, optionally scoped to a
  folder. Nothing stays on the server to re-fetch; reload ends the session.
- **Read-Write** (under *Advanced*): live sync with per-chunk keys held only
  in browser memory — zeroized on unload, never the RMS.

Every grant is time-boxed (default 30 min, server-capped at 24 h) and can be
revoked instantly from any device.

---

## 6. Verifying your install

```sh
bash security/run-scan.sh        # cargo audit + semgrep + custom scanner + cargo deny
bash security/exploits/run-exploits.sh   # exploit/regression suite
cargo test --workspace           # unit + policy tests
```

For troubleshooting the desktop front end on Wayland and theming, see
`desktopVELA/README.md`; for server deployment on systemd with a reverse
proxy, see `serverVELA/DEPLOY_SYSTEMD.md`.

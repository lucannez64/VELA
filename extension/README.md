# VELA Browser Extension

A secure password manager browser extension with zero-knowledge architecture. Works with Chrome, Firefox, and all their forks using Manifest V3.

## Features

- **Zero-Knowledge Architecture**: Your master password never leaves your device
- **Biometric Authentication**: Unlock with Windows Hello, Touch ID, or Face ID
- **Native Desktop Integration**: Communicates securely with the VELA desktop application
- **Smart Autofill**: Automatically fills login credentials on websites
- **Cross-Platform**: Works on Chrome, Edge, Brave, Thorium, Helium, Firefox, Zen, Waterfox, and more

## Architecture

The extension uses `webextension-polyfill` for cross-browser API compatibility. The build system produces browser-specific distributions from a single source tree.

### Directory Structure

```
extension/
├── _locales/              # Localization files
│   └── en/
│       └── messages.json
├── icons/                 # Extension icons
├── manifests/             # Browser-specific manifest templates
│   ├── chrome.json
│   └── firefox.json
├── native-messaging/      # Native messaging hosts
│   ├── chromium/
│   │   └── manifest.json
│   ├── firefox/
│   │   └── manifest.json
│   ├── register-host.sh          # All Chromium browsers (Linux/macOS)
│   ├── register-host.bat         # All Chromium browsers (Windows)
│   ├── register-firefox-host.sh  # All Gecko browsers (Linux/macOS)
│   ├── register-firefox-host.bat # All Gecko browsers (Windows)
│   └── vela-native-messaging-host.py
├── src/
│   ├── background/        # Service worker (background.js)
│   ├── content/           # Content scripts for autofill
│   │   ├── content-script.js
│   │   └── content-styles.css
│   ├── popup/             # Extension popup UI
│   │   ├── popup.html
│   │   └── popup.js
│   └── shared/            # Shared utilities (Bitwarden algorithms)
│       └── autofill-utils.js
├── dist/                  # Build output (generated)
│   ├── chrome/            # Chrome + all Chromium forks
│   └── firefox/           # Firefox + all Gecko forks
├── build.js               # Build script
└── package.json
```

## Build

### Prerequisites

- [Bun](https://bun.sh/) (also works with Node.js)

### Install Dependencies

```bash
bun install
```

### Build for All Browsers

```bash
bun run build
```

This produces two builds:
- `dist/chrome/` — for Chrome, Edge, Brave, Thorium, Helium, Vivaldi, Opera, Arc, and any Chromium fork
- `dist/firefox/` — for Firefox, Zen Browser, Waterfox, Floorp, LibreWolf, and any Gecko fork
- `dist/vela-firefox.xpi` — packaged Gecko extension archive

### Build for a Single Browser

```bash
bun run build:chrome
bun run build:firefox
bun run build:xpi
```

## Installation

### Chromium-based Browsers (Chrome, Edge, Brave, Thorium, Helium, etc.)

1. Run `bun run build:chrome`
2. Open your browser's extensions page:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
   - Brave: `brave://extensions/`
   - Thorium: `thorium://extensions/`
   - Helium: `helium://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked"
5. Select the `extension/dist/chrome` folder

### Gecko-based Browsers (Firefox, Zen, Waterfox, Floorp, etc.)

1. Run `bun run build:firefox`
2. Open `extension/dist/vela-firefox.xpi` in your browser to install the packaged extension.

For temporary development loading, use the debugging page:
   - Firefox: `about:debugging#/runtime/this-firefox`
   - Zen: `about:debugging#/runtime/this-firefox`
   - Waterfox: `about:debugging#/runtime/this-waterfox`
3. Click "Load Temporary Add-on"
4. Navigate to `extension/dist/firefox` and select `manifest.json`

Regular Firefox-family release builds require add-ons to be signed before they
can be installed permanently. Create API credentials in the AMO Developer Hub,
then sign an unlisted build:

```powershell
$env:WEB_EXT_API_KEY = "<amo-jwt-issuer>"
$env:WEB_EXT_API_SECRET = "<amo-jwt-secret>"
bun run sign:firefox
```

`sign:firefox` increments the patch version automatically before submitting,
because AMO rejects duplicate extension versions. The signed permanent-install
XPI is written to `extension/dist/signed/`. Keep using
`extension/dist/vela-firefox.xpi` only for browsers or profiles that allow
unsigned add-ons.

### Native Messaging Setup

Native messaging is required. The extension does not talk to localhost HTTP; it sends requests through the browser native messaging API, and the host relays them to the desktop app over an OS-protected pipe/socket with a per-session capability token.

#### All Chromium Browsers

```bash
# Linux / macOS
chmod +x native-messaging/register-host.sh native-messaging/vela-native-messaging-host.py
export VELA_CHROME_EXTENSION_ID=<your-audited-extension-id>
./native-messaging/register-host.sh
```

On Windows, set `VELA_CHROME_EXTENSION_ID` and run `native-messaging\register-host.bat`.

This registers for: Chrome, Edge, Brave, Thorium, Helium, Vivaldi, Opera, Arc.

#### All Gecko Browsers

```bash
# Linux / macOS
chmod +x native-messaging/register-firefox-host.sh native-messaging/vela-native-messaging-host.py
./native-messaging/register-firefox-host.sh
```

On Windows, run `native-messaging\register-firefox-host.bat`.

This registers for: Firefox, Zen Browser, Waterfox, Floorp, LibreWolf.

## Development

1. Install dependencies: `bun install`
2. Build: `bun run build`
3. Load the appropriate `dist/<browser>/` folder in your browser
4. Edit files in `src/`, rebuild, and reload the extension to test

### Testing Native Messaging

```bash
python3 native-messaging/vela-native-messaging-host.py
echo -e "Content-Length: 16\n\n{\"action\":\"ping\"}" | python3 native-messaging/vela-native-messaging-host.py
```

## Security

- All credentials are encrypted by the desktop app before being sent to the extension
- The extension never sees your master password or encryption keys
- Native messaging uses process isolation to prevent injection attacks
- No data is stored in the extension itself; all vault data stays in the desktop app

## Browser Compatibility

### Supported Browsers

The `dist/chrome/` build works with **any Chromium-based browser**. The `dist/firefox/` build works with **any Gecko-based browser**.

| Browser | Build | Notes |
|---|---|---|
| Google Chrome | `dist/chrome/` | Full support |
| Microsoft Edge | `dist/chrome/` | Full support |
| Brave | `dist/chrome/` | Full support |
| Thorium | `dist/chrome/` | Full support, same registry as Chrome |
| Helium | `dist/chrome/` | Full support |
| Vivaldi | `dist/chrome/` | Full support |
| Opera | `dist/chrome/` | Full support |
| Arc | `dist/chrome/` | Full support |
| Firefox | `dist/firefox/` | Full support |
| Zen Browser | `dist/firefox/` | Full support, uses `~/.zen/` config |
| Waterfox | `dist/firefox/` | Full support |
| Floorp | `dist/firefox/` | Full support |
| LibreWolf | `dist/firefox/` | Full support |

### Native Messaging: Chromium Forks

All Chromium forks use the same native messaging protocol. The host manifest must name the audited extension ID exactly as `chrome-extension://<id>/`; wildcard origins are rejected by the registration scripts. Each fork reads the host manifest from its own config directory, and the registration scripts handle all known paths.

### Native Messaging: Gecko Forks

Zen Browser, Waterfox, Floorp, and LibreWolf use the same native messaging protocol as Firefox. They match by extension ID (`vela@vela.app`) via `allowed_extensions`. Each fork reads from its own profile config directory — the registration scripts handle all known paths.

### Feature Differences

| Feature | Chromium | Gecko |
|---|---|---|
| Service Worker | Yes | No (uses background scripts) |
| `chrome.dom.openOrClosedShadowRoot` | Yes | No (falls back to open shadow roots only) |
| `chrome.action.openPopup` | Yes | No (falls back to opening popup as tab) |
| `idle` permission | Yes | No (removed from Gecko manifest) |
| `wasm-unsafe-eval` CSP | Yes | No (removed from Gecko manifest) |
| Native Messaging scheme | `chrome-extension://` | `moz-extension://` |

## License

Proprietary - VELA Team

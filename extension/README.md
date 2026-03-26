# VELA Browser Extension

A secure password manager browser extension with zero-knowledge architecture. Works with both Firefox and Chrome-based browsers using Manifest V3.

## Features

- **Zero-Knowledge Architecture**: Your master password never leaves your device
- **Biometric Authentication**: Unlock with Windows Hello, Touch ID, or Face ID
- **Native Desktop Integration**: Communicates securely with the VELA desktop application
- **Smart Autofill**: Automatically fills login credentials on websites
- **Cross-Platform**: Works on Chrome, Edge, Firefox, and other Chromium-based browsers

## Architecture

The extension uses the same proven algorithms as Bitwarden for:
- DOM element detection and autofill
- Domain matching for credential lookup
- Form field identification

### Directory Structure

```
extension/
├── _locales/              # Localization files
│   └── en/
│       └── messages.json  # English translations
├── icons/                 # Extension icons
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
├── native-messaging/      # Native messaging host
│   ├── chrome/
│   │   └── manifest.json
│   └── vela-native-messaging-host.py
└── manifest.json         # Extension manifest (MV3)
```

## Installation

### Chrome / Edge (Chromium-based)

1. Open Chrome/Edge and go to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select the `extension` folder
5. The VELA icon should appear in your toolbar

### Firefox

1. Open Firefox and go to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Navigate to the `extension` folder and select `manifest.json`
4. Click "Open" to install temporarily

### Native Messaging Setup

For the extension to communicate with the VELA desktop app:

#### Windows

1. Copy the `native-messaging` folder to your installation directory
2. For Chrome, add a registry key:
   ```
   HKEY_LOCAL_MACHINE\SOFTWARE\Google\Chrome\NativeMessagingHosts\vela-desktop
   ```
   Set its value to the path of `native-messaging/chrome/manifest.json`

#### macOS / Linux

1. Copy `vela-native-messaging-host.py` to a secure location
2. Make it executable: `chmod +x vela-native-messaging-host.py`
3. Create a config file at `~/.config/vela/native-messaging-host.json`:
   ```json
   {
     "description": "VELA Native Messaging Host",
     "path": "/path/to/vela-native-messaging-host.py",
     "type": "stdio"
   }
   ```

## Development

### Building from Source

The extension is written in pure JavaScript with no build step required for basic usage. To test changes:

1. Make changes to the source files
2. Go to `chrome://extensions/`
3. Click the refresh icon on the VELA extension card

### Testing

```bash
# Run the Python native messaging host test
python3 native-messaging/vela-native-messaging-host.py

# Test with a simple ping
echo -e "Content-Length: 16\n\n{\"action\":\"ping\"}" | python3 native-messaging/vela-native-messaging-host.py
```

## Security

- All credentials are encrypted by the desktop app before being sent to the extension
- The extension never sees your master password or encryption keys
- Native messaging uses process isolation to prevent injection attacks
- No data is stored in the extension itself; all vault data stays in the desktop app

## Algorithms

The extension uses Bitwarden's proven algorithms for:

### Domain Matching
- Exact domain matching (e.g., `login.example.com`)
- Subdomain matching (e.g., `*.example.com`)
- Handles special cases like `www` prefix and IP addresses

### DOM Element Detection
- Queries form elements including Shadow DOM
- Uses multiple heuristics for field identification:
  - HTML attributes (name, id, class, title)
  - Autocomplete attributes
  - Label associations
  - Position relative to other fields
- Filters out non-login fields (search, captcha, etc.)

### Field Classification
- Password fields (type="password")
- Username fields (text, email, tel)
- TOTP/2FA fields
- Credit card fields
- Identity fields

## License

Proprietary - VELA Team

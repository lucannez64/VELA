# VELA Native Messaging Host

This directory contains the native messaging bridge between the VELA browser extension and the VELA desktop application.

## How It Works

The extension communicates with the desktop app via two channels:
1. **HTTP** (primary) — `http://localhost:14597/` — works without native messaging setup
2. **Native Messaging** (fallback) — OS-specific IPC protocol — requires registration

## Registration Scripts

| Script | Platform | Registers for |
|---|---|---|
| `register-host.sh` | Linux/macOS | Chrome, Edge, Brave, Thorium, Helium, Vivaldi, Opera, Arc |
| `register-host.bat` | Windows | Chrome, Edge, Brave, Thorium, Helium, Vivaldi, Opera, Arc |
| `register-firefox-host.sh` | Linux/macOS | Firefox, Zen, Waterfox, Floorp, LibreWolf, Thunderbird |
| `register-firefox-host.bat` | Windows | Firefox, Zen, Waterfox, Floorp, LibreWolf |

### Quick Start

```bash
# All Chromium-based browsers
chmod +x native-messaging/vela-native-messaging-host.py
chmod +x native-messaging/register-host.sh
./native-messaging/register-host.sh

# All Gecko-based browsers
chmod +x native-messaging/register-firefox-host.sh
./native-messaging/register-firefox-host.sh
```

## Browser Compatibility

### Chromium Forks (use `chrome-extension://` scheme)

All Chromium forks share the same extension loading mechanism and native messaging protocol. The `chrome-extension://*` wildcard in the native messaging host manifest covers all of them.

| Browser | Registry (Windows) | Config (Linux) | Config (macOS) |
|---|---|---|---|
| Google Chrome | `HKCU\SOFTWARE\Google\Chrome` | `~/.config/google-chrome/` | `~/Library/Application Support/Google/Chrome/` |
| Microsoft Edge | `HKCU\SOFTWARE\Microsoft\Edge` | `~/.config/microsoft-edge/` | `~/Library/Application Support/Microsoft Edge/` |
| Brave | `HKCU\SOFTWARE\BraveSoftware\Brave-Browser` | `~/.config/BraveSoftware/Brave-Browser/` | `~/Library/Application Support/BraveSoftware/Brave-Browser/` |
| Thorium | `HKCU\SOFTWARE\Thorium` | `~/.config/thorium/` | `~/Library/Application Support/Thorium/` |
| Helium | `HKCU\SOFTWARE\Helium` | `~/.config/helium/` | `~/Library/Application Support/Helium/` |
| Vivaldi | `HKCU\SOFTWARE\Vivaldi` | `~/.config/vivaldi/` | `~/Library/Application Support/Vivaldi/` |
| Opera | `HKCU\SOFTWARE\Opera Software\Opera Stable` | `~/.config/opera/` | `~/Library/Application Support/com.operasoftware.Opera/` |
| Arc | `HKCU\SOFTWARE\The Browser Company\Arc` | `~/.config/Arc/` | `~/Library/Application Support/Arc/` |

### Gecko Forks (use `moz-extension://` scheme)

All Gecko-based browsers (Firefox and forks) share the same native messaging protocol. They use `allowed_extensions` (not `allowed_origins`) and match by extension ID.

| Browser | Config (Linux) | Config (macOS) | Config (Windows) |
|---|---|---|---|
| Firefox | `~/.mozilla/native-messaging-hosts/` | `~/Library/Application Support/Mozilla/` | `%APPDATA%\Mozilla\NativeMessagingHosts\` |
| Zen Browser | `~/.zen/native-messaging-hosts/` | `~/Library/Application Support/zen/` | `%APPDATA%\zen\NativeMessagingHosts\` |
| Waterfox | `~/.waterfox/native-messaging-hosts/` | `~/Library/Application Support/Waterfox/` | `%APPDATA%\Waterfox\NativeMessagingHosts\` |
| Floorp | `~/.floorp/native-messaging-hosts/` | `~/Library/Application Support/Floorp/` | `%APPDATA%\Floorp\NativeMessagingHosts\` |
| LibreWolf | `~/.librewolf/native-messaging-hosts/` | `~/Library/Application Support/librewolf/` | `%APPDATA%\librewolf\NativeMessagingHosts\` |

## Testing

```bash
python3 native-messaging/vela-native-messaging-host.py
echo -e "Content-Length: 16\n\n{\"action\":\"ping\"}" | python3 native-messaging/vela-native-messaging-host.py
```

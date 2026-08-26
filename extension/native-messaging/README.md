# VELA Native Messaging Host

This directory contains the registration manifests and scripts for the native messaging bridge between the VELA browser extension and the VELA desktop application.

## How It Works

The extension communicates with the desktop app only through browser native
messaging. The browser spawns a single self-contained binary —
`vela-native-messaging-host`, built from `desktopVELA/vela-nm-host` — over
stdio, and it relays framed messages to the desktop app over a well-known
per-user endpoint (a Unix socket under `XDG_RUNTIME_DIR/vela-<uid>/`, or a
named pipe on Windows).

**There is no capability file and no shared secret.** The desktop does not
authenticate what the host *says*; it authenticates what the kernel says about
*who connected* (`vela-desktop-core`'s `ipc_gate`): same user, the VELA host
binary, started by a browser. An arbitrary process running as the user can no
longer read a token off disk and talk to the vault (issue #149, option B;
retires finding #69).

The Chromium/Gecko native messaging host name is `com.vela.desktop`. Do not use
the previous `vela-desktop` name; Chromium rejects host names that contain
hyphens before it even reads the registered manifest.

### Building the host

```bash
cd desktopVELA && cargo build --release -p vela-nm-host
# -> desktopVELA/target/release/vela-native-messaging-host
```

The registration scripts look for it in the usual install locations
(`/usr/bin`, `/usr/local/bin`, `~/.local/bin`) and in the workspace target
directory; set `VELA_NM_HOST_PATH` to point at one anywhere else.

## Registration Scripts

| Script | Platform | Registers for |
|---|---|---|
| `register-host.sh` | Linux/macOS | Chrome, Edge, Brave, Thorium, Helium, Vivaldi, Opera, Arc |
| `register-host.bat` | Windows | Chrome, Edge, Brave, Thorium, Helium, Vivaldi, Opera, Arc |
| `register-firefox-host.sh` | Linux/macOS | Firefox, Zen, Waterfox, Floorp, LibreWolf, Thunderbird |
| `register-firefox-host.bat` | Windows | Firefox, Zen, Waterfox, Floorp, LibreWolf |

### Quick Start

```bash
# Build the host binary once
cd desktopVELA && cargo build --release -p vela-nm-host && cd ..

# All Chromium-based browsers
./native-messaging/register-host.sh

# All Gecko-based browsers
./native-messaging/register-firefox-host.sh
```

## Browser Compatibility

### Chromium Forks (use `chrome-extension://` scheme)

All Chromium forks share the same extension loading mechanism and native messaging protocol. Registration requires `VELA_CHROME_EXTENSION_ID` and writes a single `chrome-extension://<id>/` origin. Wildcard origins are not allowed.

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

On Windows, Zen may discover Gecko native messaging hosts through
`HKCU\SOFTWARE\Mozilla\NativeMessagingHosts\<host name>`. The Windows Gecko
registration script writes this registry key in addition to the browser-specific
manifest files.

## Testing

The host speaks the native messaging protocol: every message is a 4-byte
little-endian *length* prefix followed by the JSON — there is no length prefix
in a bare `echo`, so a raw `echo '{"action":"ping"}' | vela-native-messaging-host`
reads garbage as the length and prints nothing.

More importantly, the desktop's `ipc_gate` only admits a host that a **browser**
spawned (gate checks 1–3 in `ipc_gate.rs`). A host you launch from a terminal
has no browser in its process ancestry, so the desktop refuses it and the host
answers `{"success":false,"connected":false}`. That is expected, not a bug —
the manual command can never return `{"success":true,...}`.

To confirm the binary and the desktop socket are wired up at all, send a
*framed* ping from a shell (you will see `connected:false`, proving the path
works and isolating any real problem to the gate):

```bash
cd ../../desktopVELA && cargo build --release -p vela-nm-host
python3 - <<'PY'
import json, subprocess, sys
m = json.dumps({"action":"ping"}).encode()
p = subprocess.run(
    ["../desktopVELA/target/release/vela-native-messaging-host"],
    input=len(m).to_bytes(4,"little")+m, capture_output=True)
out = p.stdout
print("response:", out[4:].decode() if len(out) > 4 else f"(none; stderr: {p.stderr.decode().strip()})")
PY
```

The only faithful end-to-end test is the browser extension itself: that is what
spawns the host as a browser descendant and passes the gate. The host plus the
real gate and socket are also covered by `vela-nm-host`'s `e2e` test (it stands
in for the browser via the `VELA_NM_BROWSER_NAMES` escape hatch).

If the extension does not work, the desktop log is the source of truth — look
for a line like:

```
WARN … Refused IPC connection from vela-native-messaging-host (pid …): … was not started by a recognized browser
```

which means the gate could not find a browser in the host's ancestry (common
with Flatpak/Snap browsers, whose host parent is the sandbox launcher rather
than `chrome`/`firefox`). The escape hatch is `VELA_NM_BROWSER_NAMES=<launcher>`
on the **desktop** process.

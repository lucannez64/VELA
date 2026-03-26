# VELA Browser Extension - Setup Guide

## Overview

The VELA browser extension communicates with the desktop app via a TCP socket connection on `localhost:14597`.

### Communication Flow

```
Browser Extension 
    → Native Messaging Host (Python)
    → VELA Desktop App (TCP port 14597)
```

## Prerequisites

1. VELA Desktop App running on Windows
2. Python 3.x with the native messaging host installed
3. Chrome, Edge, or Firefox browser

## Setup Steps

### 1. Build and Run Desktop App

The desktop app must be running and listening on port 14597:

```bash
cd desktopVELA/src-tauri
cargo build
./target/debug/vela-desktop.exe
```

The app will start an IPC server on `127.0.0.1:14597`.

### 2. Register Native Messaging Host

For Chrome/Edge, run the registration script as Administrator:

```bash
cd extension/native-messaging
register-host.bat
```

Or manually add to Windows Registry:

```
HKEY_CURRENT_USER\SOFTWARE\Google\Chrome\NativeMessagingHosts\vela-desktop
Value: C:\Program Files\VELA\native-messaging-host\chrome\manifest.json
```

For Firefox, the extension handles native messaging automatically.

### 3. Load Extension in Browser

**Chrome/Edge:**
1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `extension` folder

**Firefox:**
1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `extension/manifest.json`

## Testing

### Test Desktop App IPC Server

```bash
# Start desktop app first, then:
telnet localhost 14597
```

Type: `{"msg_type": "Ping", "payload": {}}\n`

Expected response: `{"msg_type": "Pong", "payload": {"connected": true}}`

### Test Native Messaging Host

```bash
python native-messaging/vela-native-messaging-host.py
# Then type (separate lines):
# Content-Length: 16
# {"action":"ping"}
```

## Troubleshooting

### "Desktop app not connected"

1. Verify desktop app is running
2. Check if port 14597 is accessible: `netstat -an | findstr 14597`
3. Disable firewall temporarily to test
4. Check extension logs in browser dev tools

### "Native messaging not available"

1. Re-run `register-host.bat` as Administrator
2. Restart browser
3. Verify manifest.json path in registry

## Security Notes

- The IPC server only accepts connections from localhost
- Each browser extension instance is isolated
- No credentials are stored in the extension itself

#!/usr/bin/env bash
# A genuine GPUI macOS launch with a disposable demo vault. No real credentials.
set -euo pipefail
if [[ $(uname -s) != Darwin ]]; then
  echo 'This smoke check requires macOS.' >&2
  exit 2
fi
binary="$1"
output="$2"
test -x "$binary"
mkdir -p "$output"
app="$output/VELA GPUI Preview.app"
mkdir -p "$app/Contents/MacOS"
cp "$binary" "$app/Contents/MacOS/vela-desktop"
python3 - "$app/Contents/Info.plist" <<'PY'
import plistlib, sys
with open(sys.argv[1], 'wb') as target:
    plistlib.dump({
        'CFBundleExecutable': 'vela-desktop',
        'CFBundleIdentifier': 'com.vela.vault.gpui-preview',
        'CFBundleName': 'VELA GPUI Preview',
        'CFBundlePackageType': 'APPL',
        'CFBundleShortVersionString': '0.1.0',
        'CFBundleVersion': '1',
        'LSMinimumSystemVersion': '11.0',
        'NSHighResolutionCapable': True,
        'NSPrincipalClass': 'NSApplication',
    }, target)
PY
# Ad-hoc signature for this CI preview. This is not a notarized release build.
codesign --force --deep --sign - "$app"
codesign --verify --deep --strict "$app"
RUST_LOG=info "$app/Contents/MacOS/vela-desktop" --demo >"$output/startup.log" 2>&1 &
app_pid=$!
trap 'kill "$app_pid" 2>/dev/null || true' EXIT
sleep 15
if ! kill -0 "$app_pid" 2>/dev/null; then
  cat "$output/startup.log"
  echo 'GPUI exited before the smoke check.' >&2
  exit 1
fi
if ! grep -q 'GPUI native text fonts registered' "$output/startup.log"; then
  cat "$output/startup.log"
  echo 'GPUI did not initialize the native text backend.' >&2
  exit 1
fi
if ! grep -q 'GPUI main window opened' "$output/startup.log"; then
  cat "$output/startup.log"
  echo 'GPUI did not report an opened main window.' >&2
  exit 1
fi
screencapture -x "$output/instrument-demo.png"
test -s "$output/instrument-demo.png"
ditto -c -k --sequesterRsrc --keepParent "$app" "$output/VELA-GPUI-Preview.app.zip"
# The zip preserves executable permissions when downloaded from Actions.
rm -rf "$app"

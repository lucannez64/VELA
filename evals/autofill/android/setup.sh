#!/usr/bin/env bash
# One-time device prep for the Android autofill eval. Idempotent.
#
# Needs: an emulator started with -writable-system (for /etc/hosts), or a
# rooted device; adb on PATH; the eval server running on this machine
# (node lib/server.mjs). VELA must already be installed and signed in to a
# dedicated *test* account holding the eval vault (node lib/export-vault.mjs).
set -euo pipefail
cd "$(dirname "$0")/.."
SERIAL="${ANDROID_SERIAL:-}"
adb() { command adb ${SERIAL:+-s "$SERIAL"} "$@"; }
HOST_IP="${VELA_EVAL_HOST_IP:-10.0.2.2}"   # the host as seen from the emulator

echo "== hosts: map every fixture host to $HOST_IP"
HOSTS=$(node -e 'import("./lib/server.mjs").then(m=>console.log(m.fixtureHosts().filter(h=>h!=="localhost").join(" ")))' 2>/dev/null | tail -1)
mkdir -p .cache
adb root >/dev/null; adb wait-for-device
adb remount >/dev/null 2>&1 || { echo "remount failed: start the emulator with -writable-system"; exit 1; }
{ echo "127.0.0.1 localhost"; echo "::1 ip6-localhost"; for h in $HOSTS; do echo "$HOST_IP $h"; done; } > .cache/android-hosts
adb push .cache/android-hosts /system/etc/hosts >/dev/null

echo "== CA: push the eval CA; install it once as a user certificate"
adb push .cache/tls/ca.pem /sdcard/Download/vela-eval-ca.pem >/dev/null
echo "   Settings > Security > Encryption & credentials > Install a certificate > CA certificate > Download/vela-eval-ca.pem"
echo "   Firefox: about:config > security.enterprise_roots.enabled = true"

echo "== autofill service: VELA"
adb shell settings put secure autofill_service com.vela.android/com.vela.android.autofill.VelaAutofillService
adb shell settings get secure autofill_service

cat <<'TXT'
== manual, once per device:
   - Chrome: Settings > Autofill services > "Autofill using another service" (then restart Chrome)
   - VELA: trust each browser you will test (Settings > Autofill > Trusted browsers)
   - VELA: on the "Autofill Lab (app)" login, add the app com.vela.autofilleval.lab
   - VELA: unlock it, and set a long auto-lock so runs do not hit "Unlock VELA"
     (or pass unlock=finger and enroll an emulator fingerprint)
TXT

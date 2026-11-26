#!/usr/bin/env bash
# One-time Mac + Simulator prep for the iOS autofill eval. Run on the Mac.
# The Simulator resolves names through the Mac, so fixture hosts go in the
# Mac's /etc/hosts (needs sudo — the script prints the block, you paste it).
set -euo pipefail
cd "$(dirname "$0")/.."
test -f .cache/tls/ca.pem || { echo "start the eval server once first (node lib/server.mjs) so it creates the CA"; exit 1; }
HOSTS=$(node -e 'import("./lib/server.mjs").then(m=>console.log(m.fixtureHosts().filter(h=>h!=="localhost").join(" ")))' | tail -1)
if ! grep -q "acme-bank.test" /etc/hosts; then
  echo "== add the fixture hosts to /etc/hosts (run this, then re-run setup.sh):"
  echo "sudo sh -c 'echo \"127.0.0.1 $HOSTS\" >> /etc/hosts'"
  exit 1
fi
echo "== trust the eval CA in the booted Simulator"
xcrun simctl keychain booted add-root-cert .cache/tls/ca.pem
echo "== enroll Face ID so the server can answer VELA's prompt"
xcrun simctl spawn booted notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn booted notifyutil -p com.apple.BiometricKit.enrollmentChanged
cat <<'TXT'
== manual, once per Simulator:
   - install VELA (signed, so the AutoFill extension registers) and sign in to
     the dedicated test account holding the eval vault (node lib/export-vault.mjs)
   - Settings > General > AutoFill & Passwords: turn on VELA, turn off iCloud Passwords
   - VELA: on "Autofill Lab (app)", add dev.vela.autofilleval.lab if your build supports app links
TXT

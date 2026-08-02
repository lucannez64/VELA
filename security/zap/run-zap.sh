#!/usr/bin/env bash
#
# VELA ZAP runner — authenticated active scan of the sync API.
#
# ZAP's spider is useless on a pure JSON API (audit Phase 2 confirmed a bare
# -quickurl run times out scanning nothing). This uses ZAP's "active scan by
# URL" mode against the explicit endpoint list below, authenticated with a
# Bearer token, so the scanner actually exercises vault/share/device handlers.
#
# Prereqs:  pacman -S zaproxy   (ZAP >= 2.15)
#           get a token: python3 /tmp/opencode/exploit_idor_ratelimit.py style
#           registration against a running instance, or set VELA_TEST_TOKEN.
#
# Usage:    VELA_BASE=http://127.0.0.1:8553 VELA_TEST_TOKEN=<paseto> \
#             security/zap/run-zap.sh

set -u
BASE="${VELA_BASE:-http://127.0.0.1:8553}"
TOK="${VELA_TEST_TOKEN:-}"
OUT=/tmp/vela-zap-report.html

if [ -z "$TOK" ]; then
  echo "Set VELA_TEST_TOKEN to an authenticated PASETO for the target instance." >&2
  exit 2
fi
command -v zaproxy >/dev/null 2>&1 || { echo "zaproxy not installed (pacman -S zaproxy)" >&2; exit 2; }

# Endpoints worth active-scanning (authenticated data-plane handlers).
# Health/recovery are out of scope: recovery is pre-auth by design, health is liveness.
TARGETS=(
  "$BASE/device/capsule"
  "$BASE/devices"
  "$BASE/vault/chunk/id1"
  "$BASE/vault/sync"
  "$BASE/share/inbox"
  "$BASE/share/linked"
  "$BASE/share/my-ek"
  "$BASE/share/recipient/00000000-0000-0000-0000-000000000000/ek"
)

cmd=(zaproxy -cmd -daemon -port 18080)
for t in "${TARGETS[@]}"; do
  cmd+=( -active-scan -url "$t" -auth-header "Authorization: Bearer $TOK" )
done
cmd+=( -scan-report "$OUT" )

echo "Running ZAP active scan against ${BASE} (${#TARGETS[@]} targets)..."
"${cmd[@]}"
echo "Report: $OUT"

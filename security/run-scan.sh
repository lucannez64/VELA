#!/usr/bin/env bash
#
# VELA security scan (local + CI).
#
# Layers:
#   1. cargo-audit        dependency advisories (serverVELA + libVELA crates)
#   2. semgrep vela-js.yml  extension JS rules (unescaped attr, native bypass)
#   3. scan.py            Rust rules (missing-authsession, debug-format-crypto,
#                         panic-across-ffi) — dependency-free, works everywhere
#
# Exit code: 0 = clean, 1 = findings, 2 = setup problem.
#
# Uses the local semgrep if found (venv, pipx, or PATH). The osemgrep pip build
# cannot target .rs via YAML (see SECURITY_AUDIT.md Phase 2), so Rust rules run
# through scan.py; semgrep/vela.yml is the canonical rule set for CI semgrep.

set -u
cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
fail=0

# ---- locate semgrep ----
SEMGREP="${SEMGREP_BIN:-}"
for c in \
  "$SEMGREP" \
  /tmp/opencode/semgrep-venv/bin/semgrep \
  "$HOME"/.local/bin/semgrep \
  "$(command -v semgrep 2>/dev/null || true)"; do
  if [ -n "$c" ] && [ -x "$c" ]; then SEMGREP="$c"; break; fi
done

if [ -n "$SEMGREP" ]; then
  echo "== semgrep — extension JS rules ($(basename "$(dirname "$SEMGREP")")) =="
  "$SEMGREP" scan --config "$ROOT/security/semgrep/vela-js.yml" --json \
    "$ROOT/extension/src" > /tmp/vela-semgrep.json 2>/dev/null
  n=$(python3 -c "import json;print(len(json.load(open('/tmp/vela-semgrep.json'))['results']))" 2>/dev/null || echo "?")
  echo "  findings: $n"
  if [ "${n:-0}" != "0" ]; then fail=1; fi
else
  echo "== semgrep: not found, skipping (install via pipx or use security/venv) =="
fi

# ---- scan.py (Rust rules) ----
echo
echo "== scan.py — Rust rules =="
python3 "$ROOT/security/scan.py"
rc=$?
[ "$rc" -ne 0 ] && fail=1

# ---- cargo-audit ----
audit_one() {
  local dir="$1"
  echo "== cargo-audit — $(basename "$dir") =="
  local out
  out=$( ( cd "$dir" && cargo audit --quiet 2>&1 ) )
  if echo "$out" | grep -qE "^error|vulnerability found|Vulnerable"; then
    echo "$out" | grep -E "Crate:|Title:|ID:|Vulnerable|error:" | head -12
    fail=1
  else
    echo "  clean (no advisories)"
  fi
}
if command -v cargo-audit >/dev/null 2>&1; then
  audit_one "$ROOT/serverVELA"
  audit_one "$ROOT/libVELA/vela-crypto"
  audit_one "$ROOT/libVELA/vela-android-bridge"
  audit_one "$ROOT/libVELA/vela-wasm-bridge"
  audit_one "$ROOT/libVELA/vela-core"
else
  echo "== cargo-audit: not installed, skipping (cargo install cargo-audit) =="
fi

# ---- cargo-deny (dependency policy: bans/licenses) ----
deny_one() {
  local dir="$1"
  echo "== cargo-deny — $(basename "$dir") =="
  local out rc
  out=$(cd "$dir" && cargo deny --config "$ROOT/security/deny.toml" check 2>&1)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "  clean (bans + licenses ok)"
  else
    echo "$out" | grep -E "^error\[" | head -10
    fail=1
  fi
}
if command -v cargo-deny >/dev/null 2>&1; then
  deny_one "$ROOT/serverVELA"
  deny_one "$ROOT/libVELA/vela-crypto"
  deny_one "$ROOT/libVELA/vela-android-bridge"
  deny_one "$ROOT/libVELA/vela-wasm-bridge"
  deny_one "$ROOT/libVELA/vela-core"
else
  echo "== cargo-deny: not installed, skipping (cargo install cargo-deny) =="
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "VELA security scan: PASS"
else
  echo "VELA security scan: FAIL (see findings above)"
fi
exit "$fail"

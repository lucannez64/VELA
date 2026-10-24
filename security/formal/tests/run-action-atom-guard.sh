#!/usr/bin/env bash
# Regression for the action-atom source guard.
# Pass: the real M28/M29 models use only emitted action atoms.
# Fail: a formula over a state fact (the historical vacuity shape) is rejected.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
guard="$root/check-action-atoms.py"

python3 "$guard" \
  "$root/m28_share_journal.spthy" \
  "$root/m29_signed_share_commit.spthy"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
if python3 "$guard" "$root/tests/vacuous-action-atom.spthy" >"$tmp" 2>&1; then
  echo "action-atom guard FAILED to reject the vacuous fixture" >&2
  cat "$tmp" >&2
  exit 1
fi
for expected in 'DiskClean/5' 'RealAction/2'; do
  if ! grep -q "$expected" "$tmp"; then
    echo "action-atom guard missed $expected" >&2
    cat "$tmp" >&2
    exit 1
  fi
done

echo "action-atom guard regression: real models pass, undeclared name and wrong arity rejected"

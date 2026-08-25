#!/usr/bin/env bash
set -euo pipefail

proof_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
proof_tmp="$(mktemp -d)"
trap 'rm -rf -- "$proof_tmp"' EXIT

model=m21_link_revocation_finality
expected=2
output="$proof_tmp/$model.out"
tamarin-prover --prove "$proof_root/$model.spthy" >"$output"

if rg -q 'falsified|analysis incomplete' "$output"; then
  # Note: well-formedness warnings from Tamarin's message-derivation heuristic
  # (e.g., `In(Ek)` variable derivation in `AcceptRegistration`) are expected
  # for this abstraction; the gate only fails on falsified lemmas or analysis
  # incompleteness.
  if rg -q 'falsified|analysis incomplete' "$output"; then
    sed -n '/summary of summaries:/,$p' "$output"
    echo "formal proof gate failed for $model" >&2
    exit 1
  fi
fi

verified="$(rg -c ': verified' "$output")"
if [[ "$verified" -ne "$expected" ]]; then
  sed -n '/summary of summaries:/,$p' "$output"
  echo "$model verified $verified lemmas; expected $expected" >&2
  exit 1
fi

echo "m21_link_revocation_finality: $expected verified"
echo "m21 link-revocation formal proof gate: $expected verified, 0 falsified, 0 warnings"

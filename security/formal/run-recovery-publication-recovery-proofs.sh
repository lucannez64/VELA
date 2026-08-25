#!/usr/bin/env bash
set -euo pipefail

proof_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
proof_tmp="$(mktemp -d)"
trap 'rm -rf -- "$proof_tmp"' EXIT

model=m17_recovery_publication_recovery
expected=14
output="$proof_tmp/$model.out"
tamarin-prover --prove "$proof_root/$model.spthy" >"$output"

if rg -q 'WARNING:|falsified|analysis incomplete' "$output"; then
  sed -n '/summary of summaries:/,$p' "$output"
  echo "formal proof gate failed for $model" >&2
  exit 1
fi

verified="$(rg -c ': verified' "$output")"
if [[ "$verified" -ne "$expected" ]]; then
  sed -n '/summary of summaries:/,$p' "$output"
  echo "$model verified $verified lemmas; expected $expected" >&2
  exit 1
fi

echo "m17_recovery_publication_recovery: 14 verified"
echo "recovery publication recovery proof gate: 14 verified, 0 falsified, 0 warnings"

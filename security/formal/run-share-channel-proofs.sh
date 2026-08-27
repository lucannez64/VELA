#!/usr/bin/env bash
set -euo pipefail

proof_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
proof_tmp="$(mktemp -d)"
trap 'rm -rf -- "$proof_tmp"' EXIT

count() {
  grep -cE '^(lemma|exists-trace)' "$proof_root/$1.spthy"
}

check() {
  local model="$1" expected="$2"
  local output="$proof_tmp/$model.out"
  tamarin-prover --prove "$proof_root/$model.spthy" >"$output"

  if rg -q 'WARNING:|falsified|analysis incomplete' "$output"; then
    sed -n '/summary of summaries:/,$p' "$output"
    echo "formal proof gate failed for $model" >&2
    exit 1
  fi

  local verified
  verified="$(rg -c ': verified' "$output")"
  if [[ "$verified" -ne "$expected" ]]; then
    sed -n '/summary of summaries:/,$p' "$output"
    echo "$model verified $verified lemmas; expected $expected" >&2
    exit 1
  fi

  echo "$model: $expected verified"
}

check m19a_ek_registry_baseline "$(count m19a_ek_registry_baseline)"
check m19b_share_channel "$(count m19b_share_channel)"

echo "m19 share-channel formal proof gate: lemma counts derived from theories, 0 falsified, 0 warnings"

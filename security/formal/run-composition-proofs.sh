#!/usr/bin/env bash
set -euo pipefail

proof_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
proof_tmp="$(mktemp -d)"
trap 'rm -rf -- "$proof_tmp"' EXIT

# Expected lemma counts are derived from the theories themselves, so adding a
# lemma to a model updates the gate automatically. Fail-closed checks still
# apply: any falsified lemma, Tamarin warning, or incomplete analysis fails.
gate() {
  local model="$1"
  local expected verified
  expected="$(grep -cE '^(lemma|exists-trace)' "$proof_root/$model.spthy")"
  local output="$proof_tmp/$model.out"
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

  echo "$model: $expected verified"
}

gate m26_composition
gate m26a_recovery_provenance

echo "m26 composition formal proof gate: all lemmas verified, 0 falsified, 0 warnings"

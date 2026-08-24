#!/usr/bin/env bash
set -euo pipefail

proof_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
proof_tmp="$(mktemp -d)"
trap 'rm -rf -- "$proof_tmp"' EXIT

models=(
  m11_rekey_epoch_state_machine
  m11b_rekey_capsule_binding
  m11c_rekey_mutation_authority
)
expected=(15 4 12)
total=0

for index in "${!models[@]}"; do
  model="${models[$index]}"
  output="$proof_tmp/$model.out"
  tamarin-prover --prove "$proof_root/$model.spthy" >"$output"

  if rg -q 'WARNING:|falsified|analysis incomplete' "$output"; then
    sed -n '/summary of summaries:/,$p' "$output"
    echo "formal proof gate failed for $model" >&2
    exit 1
  fi

  verified="$(rg -c ': verified' "$output")"
  if [[ "$verified" -ne "${expected[$index]}" ]]; then
    sed -n '/summary of summaries:/,$p' "$output"
    echo "$model verified $verified lemmas; expected ${expected[$index]}" >&2
    exit 1
  fi
  total=$((total + verified))
  echo "$model: $verified verified"
done

if [[ "$total" -ne 31 ]]; then
  echo "rekey proof total was $total; expected 31" >&2
  exit 1
fi
echo "rekey formal proof gate: 31 verified, 0 falsified, 0 warnings"

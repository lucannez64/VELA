#!/usr/bin/env bash
# M22 · Path-ORAM access-pattern hiding (ProVerif observational equivalence).
#
# Three theories:
#   m22a  static position map  → equivalence FALSE (expected; the attack)
#   m22b  trivial-ORAM mode    → equivalence TRUE
#   m22c  path-ORAM w/ remap   → equivalence TRUE
#
# The hax-extracted policy (lib.pvl, from vela_crypto::oram) and the vendored
# prelude are concatenated ahead of each model.
set -euo pipefail

proof_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$proof_root/../.."
proof_tmp="$(mktemp -d)"
trap 'rm -rf -- "$proof_tmp"' EXIT

export PATH="$(opam var bin --switch vela-proverif 2>/dev/null):$PATH"
command -v proverif >/dev/null || {
  echo "proverif is missing; install with:" >&2
  echo "  opam switch create vela-proverif ocaml-base-compiler.5.1.1" >&2
  echo "  opam install --switch vela-proverif --yes proverif" >&2
  exit 1
}

prelude="$proof_root/hax_pv_prelude.pvl"
extracted="$repo_root/libVELA/vela-crypto/proofs/proverif/extraction/lib.pvl"

run_model() {
  local model="$1" expect_true="$2"
  local combined="$proof_tmp/$model.full.pv"
  cat "$prelude" "$extracted" "$proof_root/$model.pv" > "$combined"
  timeout 300 proverif -in pitype "$combined" > "$proof_tmp/$model.out"

  if rg -q 'WARNING|Error' "$proof_tmp/$model.out"; then
    tail -12 "$proof_tmp/$model.out"
    echo "m22 gate failed for $model: proverif reported an error/warning" >&2
    exit 1
  fi

  if [[ "$expect_true" == true ]]; then
    if ! rg -q 'Equivalence between process 1 and process 2 is true' "$proof_tmp/$model.out"; then
      sed -n '/Verification summary:/,$p' "$proof_tmp/$model.out"
      echo "m22 gate failed for $model: equivalence not proved" >&2
      exit 1
    fi
    echo "$model: equivalence TRUE (verified)"
  else
    if ! rg -q 'cannot be proved' "$proof_tmp/$model.out"; then
      sed -n '/Verification summary:/,$p' "$proof_tmp/$model.out"
      echo "m22 gate failed for $model: baseline attack was NOT found" >&2
      exit 1
    fi
    echo "$model: equivalence FALSE (baseline attack demonstrated, as expected)"
  fi
}

run_model m22a_static_position_baseline false
run_model m22b_trivial_oram_hiding     true
run_model m22c_path_oram_hiding        true

echo "m22 oram access-hiding formal proof gate: 2 equivalences proved, 1 baseline falsified, 0 errors"

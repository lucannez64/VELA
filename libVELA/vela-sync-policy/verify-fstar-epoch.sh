#!/usr/bin/env bash
set -euo pipefail

# Focused F-5 kernel: mobile clients require the manifest epoch and their
# authenticated local epoch to be exactly equal and positive. This is checked
# in a separate invocation from the historical eleven-contract module;
# that extraction stays byte-identical. The focused artifact lives under
# proofs/fstar/extraction-epoch.
#
# Two things are checked here:
#   1. the hax extraction of `plan_sync_epoch_match` and its three concrete
#      witnesses (`extraction-epoch/`); and
#   2. hand-written parametric lemmas (accepted => positive/equal, converse,
#      and the full decision == independent predicate) in `epoch-lemmas/`.
# The lemmas quantify over all inputs, so the kernel is not merely a
# definitional wrapper plus three examples.
proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow ../vela-client-recovery-policy/README.md" >&2
    exit 1
  }
done

cargo test

rm -rf proofs/fstar/extraction-epoch
cargo hax into \
  --output-dir proofs/fstar/extraction-epoch \
  -i '-** +vela_sync_policy::plan_sync_epoch_match +vela_sync_policy::equal_positive_epoch_admits_download +vela_sync_policy::mismatched_positive_epoch_admits_download +vela_sync_policy::nonpositive_epoch_admits_download' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction-epoch -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no F* modules" >&2
  exit 1
fi

mapfile -t lemma_files < <(
  find proofs/fstar/epoch-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#lemma_files[@]} == 0 )); then
  echo "no hand-written epoch lemmas found" >&2
  exit 1
fi

if (( ${#proof_files[@]} != 1 || ${#lemma_files[@]} != 1 )); then
  echo 'expected exactly one focused extraction and one epoch lemma module' >&2
  exit 1
fi
python3 ../../security/formal/check-sync-chunk-proof.py --epoch \
  "${proof_files[0]}" "${lemma_files[0]}"
version=$(fstar.exe --version)
printf '%s\n' "$version"
[[ ${version%%$'\n'*} == 'F* 2025.10.06' ]] || exit 2
hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

fstar_args=(
  --cmi
  --cache_off
  --warn_error -331
  --z3rlimit 500
  --z3version 4.13.3
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib'
  --include "$hax_lib_root/proof-libs/fstar/core"
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives"
  --include "$hax_lib_root/proofs/fstar/extraction"
  --include proofs/fstar/extraction-epoch
  --include proofs/fstar/epoch-lemmas
  "${proof_files[@]}" "${lemma_files[@]}"

)
printf 'F* epoch argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
sha256sum "${proof_files[@]}" "${lemma_files[@]}"
printf '%s  %s\n' '0b7febd0c062d955831133476fba4afc8d9616b83e6be49b63d6ba10fe404393' 'proofs/fstar/extraction-epoch/Vela_sync_policy.fst' | sha256sum --check
printf '%s  %s\n' '81843c5aa65b9e1269bcd865ba5fcc957286d72de18311e48a725dfc90ee174b' 'proofs/fstar/epoch-lemmas/Vela_sync_policy_epoch_lemmas.fst' | sha256sum --check
fstar.exe "${fstar_args[@]}"

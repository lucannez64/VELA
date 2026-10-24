#!/usr/bin/env bash
set -euo pipefail

# Focused F-5 kernel: mobile clients require the manifest epoch and their
# authenticated local epoch to be exactly equal and positive. This is checked
# separately from verify-fstar.sh so the existing extraction artifact and the
# global proof manifest stay byte-identical; the new artifact lives under
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

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

fstar.exe \
  --cmi \
  --warn_error -331 \
  --z3rlimit 500 \
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
  --include "$hax_lib_root/proof-libs/fstar/core" \
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
  --include "$hax_lib_root/proofs/fstar/extraction" \
  --include proofs/fstar/extraction-epoch \
  --include proofs/fstar/epoch-lemmas \
  "${proof_files[@]}" "${lemma_files[@]}"

#!/usr/bin/env bash
set -euo pipefail

# Focused F-2/F-1 gate for the pure share-journal step (P3a).
#
# This crate is dependency-free and owns the durable phase machine between the
# two desktop share files. The gate regenerates the extraction from the Rust
# source, checks that the extraction carries no proof escapes, and then lets F*
# check the `hax_lib::ensures` postconditions:
#
#   * `step` is total (the extracted function has no precondition and no
#     `Option` result);
#   * the generation never decreases across any step;
#   * `clear_step` keeps the generation (P1 finding 1);
#   * `plan_commit` emits journal, re-arm, vault, clear in that order, with the
#     clear image keeping the persisted generation.
#
# The hand-written module additionally restates the four facts against the
# extracted definitions, so the gate does not rely on reading the Rust
# postcondition text alone.

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in cargo cargo-hax driver-hax-frontend-exporter hax-engine fstar.exe z3-4.13.3 jq python3; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow ../vela-client-share-policy/README.md" >&2
    exit 1
  }
done

cargo test

rm -rf proofs/fstar/extraction
cargo hax into \
  --output-dir proofs/fstar/extraction \
  -i '-** +vela_client_share_journal::step +vela_client_share_journal::plan_commit +vela_client_share_journal::clear_step +vela_client_share_journal::commit_is_authorized +vela_client_share_journal::next_generation +vela_client_share_journal::state_is_well_formed +vela_client_share_journal::step_result_is_sound +vela_client_share_journal::commit_effects_match_spec +vela_client_share_journal::effects_are_commit_ordered +vela_client_share_journal::effects_are_recovery_ordered +vela_client_share_journal::plan_recovery +vela_client_share_journal::recovery_plan_matches_spec' \
  fstar --z3rlimit 500

mapfile -t proof_files < <(
  find proofs/fstar/extraction -maxdepth 1 -type f -name '*.fst' -print | sort
)
mapfile -t lemma_files < <(
  find proofs/fstar/journal-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#proof_files[@]} == 0 )); then
  echo "hax generated no share-journal modules" >&2
  exit 1
fi
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed share-journal lemma module" >&2
  exit 1
fi

# Reject proof escapes and unreviewed source options in both the generated
# module and the hand-written lemmas.
python3 "$proof_root/../../security/formal/check-driver-proof-sources.py" \
  --generated "${proof_files[@]}" \
  --proof "${lemma_files[@]}" \
  --include-dir "$proof_root"

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)
if [[ -z "$hax_lib_root" || ! -d "$hax_lib_root" ]]; then
  echo "could not locate hax-lib proof libraries" >&2
  exit 1
fi

fstar.exe \
  --cmi \
  --warn_error -331 \
  --z3rlimit 500 \
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
  --include "$hax_lib_root/proof-libs/fstar/core" \
  --include "$hax_lib_root/proof-libs/fstar/rust_primitives" \
  --include "$hax_lib_root/proofs/fstar/extraction" \
  --include proofs/fstar/extraction \
  --include proofs/fstar/journal-lemmas \
  "${proof_files[@]}" "${lemma_files[@]}"

echo "share journal: total step; generation never decreases; clear keeps the generation; a commit writes journal, re-arm, vault, clear in that order"
sha256sum "${proof_files[@]}" "${lemma_files[@]}" src/lib.rs

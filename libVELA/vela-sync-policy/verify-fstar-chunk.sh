#!/usr/bin/env bash
set -euo pipefail

# Universal chunk-download admission kernel, checked against the *historical*
# 11-contract extraction artifact.
#
# `proofs/fstar/extraction/Vela_sync_policy.fst` is the artifact verify-fstar.sh
# regenerates from the historical selected set. A future focused epoch module in
# `proofs/fstar/extraction-epoch/` may have the SAME F* module name
# (`Vela_sync_policy`), so this script must run in its own fstar.exe invocation
# and must include only `proofs/fstar/extraction`. Including the epoch directory
# here would silently shadow the artifact the chunk lemmas are about.
#
# The lemmas in `proofs/fstar/chunk-lemmas/` quantify over every observation
# and are stated against the actual extracted `plan_chunk_download`; the
# independent admission predicate is written out over raw i64/option values, not
# defined by calling the implementation. Nothing here is extracted from Rust, so
# the historical artifact stays byte-identical.

proof_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$proof_root"

for command_name in fstar.exe z3-4.13.3 cargo jq; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is missing; follow ../vela-client-recovery-policy/README.md" >&2
    exit 1
  }
done

artifact=proofs/fstar/extraction/Vela_sync_policy.fst
if [[ ! -f $artifact ]]; then
  echo "missing $artifact; run ./verify-fstar.sh to regenerate it" >&2
  exit 1
fi

mapfile -t lemma_files < <(
  find proofs/fstar/chunk-lemmas -maxdepth 1 -type f -name '*.fst' -print | sort
)
if (( ${#lemma_files[@]} != 1 )); then
  echo "expected exactly one reviewed chunk-admission lemma module" >&2
  exit 1
fi

# This guard counts source declarations and rejects proof escapes/options;
# F* is the checker, and reviewed hashes establish which statement was checked.
python3 ../../security/formal/check-sync-chunk-proof.py \
  "$artifact" "${lemma_files[0]}"
python3 -m unittest discover -s ../../security/formal/tests -p test_sync_chunk_guard.py
version=$(fstar.exe --version)
printf '%s\n' "$version"
[[ ${version%%$'\n'*} == 'F* 2025.10.06' ]] || {
  echo 'unexpected F* version' >&2
  exit 2
}
sha256sum "$artifact" "${lemma_files[@]}"

hax_lib_root=$(
  cargo metadata --format-version 1 |
    jq -r '.packages[] | select(.name == "hax-lib") | .manifest_path | sub("/Cargo.toml$"; "")'
)

# No `--include proofs/fstar/extraction-epoch` here: same module name, wrong
# artifact. `--cache_off` checks the two supplied modules from source;
# imported cached libraries remain part of the trusted proof environment.
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
  --include proofs/fstar/extraction
  --include proofs/fstar/chunk-lemmas
  "$artifact" "${lemma_files[@]}"
)
printf 'F* argv:'
printf ' %q' "${fstar_args[@]}"
printf '\n'
fstar.exe "${fstar_args[@]}"

echo "chunk proof: 11 historical Rust postconditions, 20 handwritten lemmas checked"
sha256sum "$artifact" "${lemma_files[@]}"

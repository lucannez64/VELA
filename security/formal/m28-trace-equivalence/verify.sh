#!/usr/bin/env bash
# Verify the M28 encodings and the Tamarin-to-F* source bridge: the typed
# single-slot encodings (M28TraceEquivalence), the source terms (P2a), the
# source semantics with derivability and freshness (P2c), the slot projection
# (P2b), and the bridge theorem with all ten lemmas on source traces (P2d).
# This is a separate proof kernel from Tamarin; check-m28-transcription.py
# checks the F* rule transcription against the .spthy text.
#
# Run through vela-heavy (and therefore bounded.sh) on shared machines:
#   vela-heavy security/formal/m28-trace-equivalence/verify.sh
# The journal runner performs the same check under bounded.sh.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
fstar=${VELA_FSTAR_BIN:-fstar.exe}
command -v "$fstar" >/dev/null || {
  echo 'fstar.exe is missing; set VELA_FSTAR_BIN or add F* to PATH' >&2
  exit 2
}
python3 "$here/../check-m28-semantic-proof.py" "$here/M28TraceEquivalence.fst"
# The repository-wide no-escape gate covers both modules here; the focused
# semantic guard above keeps checking the pre-existing equivalence names.
python3 "$here/../check-no-proof-escapes.py"
python3 "$here/../check-m28-transcription.py"
version=$("$fstar" --version)
printf '%s\n' "$version"
[[ ${version%%$'\n'*} == 'F* 2025.10.06' ]] || {
  echo 'unexpected proof-tool version' >&2
  exit 2
}
modules=(M28TraceEquivalence M28_source_terms M28_source_semantics
         M28_slot_projection M28_source_bridge M28_source_lemmas
         M28_source_witness)
files=()
for m in "${modules[@]}"; do files+=("$here/$m.fst"); done
sha256sum "${files[@]}"
printf 'argv: --cache_off --z3rlimit 100 --z3version 4.13.3 --include %s' "$here"
printf ' %s' "${files[@]}"
printf '\n'
VELA_FSTAR_BIN="$fstar" "$here/../../assurance/bounded.sh" \
  "$here/../fstar-bounded.sh" --cache_off --z3rlimit 100 --z3version 4.13.3 \
  --include "$here" "${files[@]}"
echo "m28-trace-equivalence: F* modules verified"

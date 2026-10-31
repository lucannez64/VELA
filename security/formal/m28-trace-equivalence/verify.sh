#!/usr/bin/env bash
# Verify lifting/projection for the typed single-slot M28 encodings.
# This is a separate proof kernel from Tamarin; it checks the F* module, not
# a transcription of a Tamarin proof.
#
# Run through vela-heavy (and therefore bounded.sh) on shared machines:
#   vela-heavy security/formal/m28-trace-equivalence/verify.sh
# The journal runner performs the same check under bounded.sh.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
fstar=${VELA_FSTAR_BIN:-fstar.exe}
command -v "$fstar" >/dev/null || {
  echo "fstar.exe is missing; set VELA_FSTAR_BIN or add F* to PATH" >&2
  exit 2
}
python3 "$here/../check-m28-semantic-proof.py" "$here/M28TraceEquivalence.fst"
version=$("$fstar" --version)
printf '%s\n' "$version"
[[ ${version%%$'\n'*} == 'F* 2025.10.06' ]] || {
  echo 'unexpected proof-tool version' >&2
  exit 2
}
sha256sum "$here/M28TraceEquivalence.fst"
printf 'argv: --cache_off --z3rlimit 100 --z3version 4.13.3 %s\n' "$here/M28TraceEquivalence.fst"
VELA_FSTAR_BIN="$fstar" "$here/../../assurance/bounded.sh" \
  "$here/../fstar-bounded.sh" --cache_off --z3rlimit 100 --z3version 4.13.3 \
  "$here/M28TraceEquivalence.fst"
echo "m28-trace-equivalence: F* module verified"

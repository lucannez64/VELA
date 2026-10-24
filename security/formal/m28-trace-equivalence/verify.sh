#!/usr/bin/env bash
# Verify the machine-checked conservative-extension proof for M28.
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
"$fstar" --z3rlimit 100 --warn_error -331 \
  "$here/M28TraceEquivalence.fst"
echo "m28-trace-equivalence: F* module verified"

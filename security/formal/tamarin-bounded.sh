#!/usr/bin/env bash
# Bound each proof's wall time and the GHC heap; callers also bound the process tree.
set -euo pipefail
exec timeout --kill-after=5 "${VELA_PROOF_TIMEOUT:-180}" \
  "${VELA_TAMARIN_BIN:-tamarin-prover}" +RTS -N1 -M1500m -RTS "$@"

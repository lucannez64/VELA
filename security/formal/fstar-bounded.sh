#!/usr/bin/env bash
# Bound one F* invocation.  Callers run this under security/assurance/bounded.sh
# (and, for the repository-wide serialization rule, under vela-heavy).
set -euo pipefail
exec timeout --kill-after=5 "${VELA_PROOF_TIMEOUT:-600}" \
  "${VELA_FSTAR_BIN:-fstar.exe}" "$@"

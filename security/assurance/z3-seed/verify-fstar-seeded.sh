#!/usr/bin/env bash
# Run one verify-fstar*.sh gate with the Z3 seed shim first on PATH (plan T8).
#
#   security/assurance/z3-seed/verify-fstar-seeded.sh [--query-stats] SEED GATE [ARGS...]
#
#   --query-stats  keep F* --query_stats output in the log (per-query rlimit
#                  statistics for the rlimit inventory); checks nothing extra
#   GATE  path to a gate script, relative to the repository root
#         (e.g. libVELA/vela-sync-policy/verify-fstar-epoch.sh)
#   SEED  positive integer passed to F* as --z3seed; 0 runs the gate without
#         a seed, i.e. through the shim's pure pass-through path
#
# The gate runs cold: VELA_FSTAR_CACHE=0 keeps evidence runs out of the shared
# checked-module store, so every module is checked from source. The shim's
# per-call log lines (VELA_Z3_SEED_LOG=1) are the evidence that the flag
# reached F*. vela-heavy offloads this script to the build box by name
# (it matches verify-fstar*.sh), which is how the local evidence was produced.
set -euo pipefail

query_stats=0
if [[ ${1-} == --query-stats ]]; then
  query_stats=1
  shift
fi

if (( $# < 2 )); then
  sed -n '2,18p' "$0" >&2
  exit 2
fi

seed=$1
gate=$2
shift 2
[[ $seed =~ ^(0|[1-9][0-9]*)$ ]] || { echo "z3-seed: SEED must be a non-negative integer, got '$seed'" >&2; exit 2; }

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../../.." && pwd)
case $gate in
  /*) gate_path=$gate ;;
  *) gate_path=$root/$gate ;;
esac
[[ -x $gate_path || -f $gate_path ]] || { echo "z3-seed: no gate at $gate_path" >&2; exit 2; }

export PATH="$here:$PATH"
export VELA_Z3_SEED_LOG="${VELA_Z3_SEED_LOG:-1}"
export VELA_FSTAR_CACHE=0
if (( query_stats )); then
  export VELA_FSTAR_QUERY_STATS=1
fi
if (( seed > 0 )); then
  export VELA_Z3_SEED=$seed
else
  unset VELA_Z3_SEED
fi

printf 'z3-seed: gate=%s seed=%s\n' "$gate" "$seed"
printf 'z3-seed: fstar.exe on PATH: %s\n' "$(command -v fstar.exe)"
printf 'z3-seed: VELA_Z3_SEED=%s VELA_FSTAR_CACHE=%s query_stats=%s\n' \
  "${VELA_Z3_SEED:-<unset>}" "$VELA_FSTAR_CACHE" "$query_stats"

start=$SECONDS
status=0
"$gate_path" "$@" || status=$?
printf 'z3-seed: gate=%s seed=%s seconds=%s exit=%s\n' \
  "$gate" "$seed" "$((SECONDS - start))" "$status"
exit "$status"

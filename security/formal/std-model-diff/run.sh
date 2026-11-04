#!/usr/bin/env bash
# Entry point for the std-model differential test (plan step T7).
#
#   ./run.sh                     # 10^6 cases per operation, evidence run
#   ./run.sh --cases 10000       # CI-sized run
#   ./run.sh --log FILE          # also save the output
#
# On a developer machine this goes through ~/.local/opt/vela-tools/bin/vela-heavy,
# which mirrors the worktree to the build box and runs the whole pipeline there
# in one slot (the pipeline is named verify-fstar*.sh, so vela-heavy offloads
# it). CI calls verify-fstar-std-model-diff.sh directly; VELA_HEAVY=0 forces
# that here too.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
pipeline="$here/verify-fstar-std-model-diff.sh"

log=""
args=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --log) log=$2; shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done

heavy=${VELA_HEAVY:-$HOME/.local/opt/vela-tools/bin/vela-heavy}
if [[ ${VELA_HEAVY:-} == 0 || ${VELA_REMOTE:-} == 0 || ! -x $heavy ]] \
   || ! git -C "$here" rev-parse --show-toplevel >/dev/null 2>&1; then
  heavy=""
fi

tmp=$(mktemp "${TMPDIR:-/tmp}/t7-run.XXXXXX")
rc=0
if [[ -n $heavy ]]; then
  echo "run.sh: $heavy $pipeline ${args[*]:-}" >&2
  "$heavy" "$pipeline" "${args[@]}" >"$tmp" 2>&1 || rc=$?
else
  echo "run.sh: $pipeline ${args[*]:-}" >&2
  "$pipeline" "${args[@]}" >"$tmp" 2>&1 || rc=$?
fi
cat "$tmp"
if [[ -n $log ]]; then
  mkdir -p "$(dirname -- "$log")"
  cp "$tmp" "$log"
  echo "run.sh: log saved to $log" >&2
fi
rm -f "$tmp"
exit "$rc"

#!/usr/bin/env bash
# T8 seed-0 baseline only: add --query_stats to module checks, then exec the
# pinned F*. Sits behind security/assurance/z3-seed/fstar.exe on PATH.
real=/tmp/vela-fstar-prebuilt/fstar/bin/fstar.exe
for a in "$@"; do
  case $a in --version|--dep|--print*|--help|--find_file|--locate*) exec "$real" "$@";; esac
done
echo "qs-wrapper: exec $real --query_stats $*" >&2
exec "$real" --query_stats "$@"

#!/usr/bin/env bash
# Show that the Z3 seed shim injects --z3seed and that Z3 receives the seed.
#
#   security/assurance/z3-seed/verify-fstar-seed-probe.sh
#
# Checks a one-lemma module in a temporary directory:
#   1. no VELA_Z3_SEED   -> pure pass-through (no seed option, or seed 0)
#   2. VELA_Z3_SEED=1    -> the dumped Z3 query sets smt.random-seed 1
#   3. VELA_Z3_SEED=2    -> same dump sets smt.random-seed 2
#   4. seed shim first, then the shared F* cache shim, and the reverse order,
#      with a scratch cache store and --cache_off: both composed runs inject
#      the seed and pass.
# F* writes the seed into the query dump because it runs the Z3 build bundled
# with the pinned F* release (2025.10.06 ships Z3 4.13.3), so the dump is the
# record of what the solver received. Exits nonzero when a seed is missing.
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../../.." && pwd)
cache_shim=$root/security/assurance/fstar-cache
work=$(mktemp -d -t vela-z3-seed-probe.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
printf 'z3-seed probe: work=%s\n' "$work"
printf 'z3-seed probe: fstar=%s\n' "$(fstar.exe --version | head -1)"
printf 'z3-seed probe: z3=%s\n' "$(z3-4.13.3 --version | head -1)"

printf '%s\n' 'module Seed_probe' '' 'let add_zero (x: int) : Lemma (x + 0 = x) = ()' \
  > "$work/Seed_probe.fst"

# Z3 spells the option smt.random-seed in the F* dump; accept ':' too.
seeds_in_dump() { # dir
  grep -rhoE 'smt\.random[-_.]seed[^0-9]*[0-9]+' "$1"/queries-*.smt2 2>/dev/null |
    grep -oE '[0-9]+$' | sort -u | tr '\n' ' ' || true
}

run_case() { # name path-prefix seed [extra-fstar-args...]
  local name=$1 prefix=$2 seed=$3
  shift 3
  local dir=$work/$name status=0
  mkdir -p "$dir"
  cp "$work/Seed_probe.fst" "$dir/"
  printf '\n== %s: PATH prefix=%s VELA_Z3_SEED=%s\n' "$name" "${prefix:-<none>}" "${seed:-<unset>}"
  if [[ -n $seed ]]; then
    ( cd "$dir" &&
      PATH="$prefix$PATH" VELA_Z3_SEED="$seed" VELA_Z3_SEED_LOG=1 \
        VELA_FSTAR_CACHE="$VELA_FSTAR_CACHE" \
        fstar.exe --log_queries --query_stats "$@" Seed_probe.fst >fstar.out 2>&1 ) || status=$?
  else
    ( cd "$dir" &&
      PATH="$prefix$PATH" VELA_Z3_SEED_LOG=1 VELA_FSTAR_CACHE="$VELA_FSTAR_CACHE" \
        fstar.exe --log_queries --query_stats "$@" Seed_probe.fst >fstar.out 2>&1 ) || status=$?
  fi
  if (( status != 0 )); then
    echo "z3-seed probe: F* failed in $name (exit $status)" >&2
    tail -n 40 "$dir/fstar.out" >&2
    exit 1
  fi
  grep '^z3-seed: ' "$dir/fstar.out" || true
  grep -E 'Verified module|All verification conditions' "$dir/fstar.out" | tail -n 2 || true
  grep -hoE '\(set-option :smt\.random[-_.]seed[^)]*\)' "$dir"/queries-*.smt2 | sort -u || true
  printf 'smt.random-seed in dumped query: %s\n' "$(seeds_in_dump "$dir")"
  printf 'query dump digest: %s\n' "$(cat "$dir"/queries-*.smt2 2>/dev/null | sha256sum | cut -c1-16)"
}

export VELA_FSTAR_CACHE=0
run_case pass-through "$here:" ""
run_case seed-1 "$here:" 1
run_case seed-1-repeat "$here:" 1
run_case seed-2 "$here:" 2

expect_seed() { # case expected
  local got
  got=$(seeds_in_dump "$work/$1")
  if [[ $got != "$2 " ]]; then
    echo "z3-seed probe: $1 did not reach Z3 with seed $2 (dump has '$got')" >&2
    exit 1
  fi
}
expect_seed seed-1 1
expect_seed seed-2 2
passthrough=$(seeds_in_dump "$work/pass-through")
if [[ -n $passthrough && $passthrough != "0 " ]]; then
  echo "z3-seed probe: unseeded run did not use the default seed ('$passthrough')" >&2
  exit 1
fi
if ! cmp -s <(cat "$work/seed-1"/queries-*.smt2) <(cat "$work/seed-1-repeat"/queries-*.smt2); then
  echo "z3-seed probe: two seed-1 runs produced different dumps" >&2
  exit 1
fi
if cmp -s <(cat "$work/seed-1"/queries-*.smt2) <(cat "$work/seed-2"/queries-*.smt2); then
  echo "z3-seed probe: seed 1 and seed 2 dumps are identical" >&2
  exit 1
fi
printf 'seeded runs are deterministic and differ across seeds: yes\n'

# A PATH lookup needs the cache shim to be executable. The tracked file is
# mode 100644 in git, so the composition cases use executable copies in a
# throw-away tree that keeps the real sibling layout (z3-seed/ next to
# fstar-cache/), which is what makes the two shims skip each other's loop.
if [[ -x $cache_shim/fstar.exe ]]; then
  printf 'tracked cache shim executable: yes\n'
else
  printf 'tracked cache shim executable: NO in this worktree (composition tested on +x copies)\n'
fi
shimroot=$work/shimroot
mkdir -p "$shimroot/z3-seed" "$shimroot/fstar-cache"
cp "$here/fstar.exe" "$shimroot/z3-seed/fstar.exe"
cp "$cache_shim/fstar.exe" "$shimroot/fstar-cache/fstar.exe"
chmod +x "$shimroot/z3-seed/fstar.exe" "$shimroot/fstar-cache/fstar.exe"

store=$work/store
mkdir -p "$store"
export VELA_FSTAR_CACHE=$store
export VELA_FSTAR_CACHE_LOG=1
run_case cache-first "$shimroot/fstar-cache:$shimroot/z3-seed:" 3 --cache_off
expect_seed cache-first 3
if grep -q '^fstar-cache:' "$work/cache-first/fstar.out"; then
  printf 'cache shim ran with cache-first: yes\n'
else
  echo 'z3-seed probe: the cache shim did not run in cache-first order' >&2
  exit 1
fi

run_case seed-first "$shimroot/z3-seed:$shimroot/fstar-cache:" 3 --cache_off
expect_seed seed-first 3
if grep -q '^fstar-cache:' "$work/seed-first/fstar.out"; then
  echo 'z3-seed probe: the cache shim ran even though seed-first must bypass it' >&2
  exit 1
fi
printf 'seed-first bypasses the cache shim by design: yes (put cache first for cached seeded runs)\n'
printf '\nz3-seed probe: PASS\n'

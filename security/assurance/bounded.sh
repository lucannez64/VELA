#!/usr/bin/env bash
# Linux process-tree memory cap. Fail closed when no cgroup manager is available.
set -euo pipefail
memory_max=${VELA_MEMORY_MAX:-3G}
if [[ ${VELA_BOUNDED:-0} == 1 ]]; then exec "$@"; fi
if ! command -v systemd-run >/dev/null || ! systemctl --user show-environment >/dev/null 2>&1; then
  if [[ ${CI:-false} == true ]] && sudo -n true 2>/dev/null; then
    exec sudo -E systemd-run --scope --quiet -p MemoryMax="$memory_max" -p MemorySwapMax=0 \
      runuser -u "$(id -un)" -- env PATH="$PATH" VELA_BOUNDED=1 CARGO_BUILD_JOBS=1 OPAMJOBS=1 MAKEFLAGS=-j1 RUST_TEST_THREADS=1 \
      timeout --kill-after=10 "${VELA_STEP_TIMEOUT:-1800}" "$@"
  fi
  echo 'A user systemd manager is required for the 3 GiB process-tree cap. Use a memory-limited container on other hosts.' >&2
  exit 2
fi
exec systemd-run --user --scope --quiet -p MemoryMax="$memory_max" -p MemorySwapMax=0 \
  env VELA_BOUNDED=1 CARGO_BUILD_JOBS=1 OPAMJOBS=1 MAKEFLAGS=-j1 RUST_TEST_THREADS=1 \
  timeout --kill-after=10 "${VELA_STEP_TIMEOUT:-1800}" "$@"

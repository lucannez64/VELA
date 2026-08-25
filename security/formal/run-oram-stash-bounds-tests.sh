#!/usr/bin/env bash
# M24 · Path-ORAM stash dynamics — statistical verification over the real
# implementation, plus the hard integrity invariants.
#
# Complements m22 (ProVerif access-pattern hiding, symbolic) with what a
# symbolic model cannot express: probabilistic stash behavior driven through
# the production code path against a faithful tree-structured server
# (buckets keyed by (level, node), shared across sibling leaves).
#
# Found & fixed during M24:
#   - stale-read bug: shared buckets held outdated block copies that
#     `position()` could surface; absorption now deduplicates.
#   - unbounded stash: the same duplicates accumulated without bound
#     (max observed 4692 vs. the new deterministic dedup bound).
#   - write-back clobbering: eviction rode the freshly remapped leaf while
#     only the OLD leaf's path had been downloaded, destroying other chunks'
#     blocks in unread sibling-subtree buckets. Write-back now rides the
#     downloaded path; migration to the remapped leaf is lazy via
#     deepest_shared_level placement.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root/libVELA/vela-crypto"

cargo test --test oram_stash_bounds 2>&1 | tee /tmp/m24-oram.out

if rg -q 'FAILED|panicked' /tmp/m24-oram.out; then
  echo "m24 gate failed" >&2
  exit 1
fi

verified="$(rg -c 'test result: ok' /tmp/m24-oram.out)"
if [[ "$verified" -lt 1 ]]; then
  echo "m24 gate failed: no passing test binary" >&2
  exit 1
fi

echo "m24 oram-stash-bounds gate: 4/4 statistical + invariant tests passed"

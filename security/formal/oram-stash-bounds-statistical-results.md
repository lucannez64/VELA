# M24 Path-ORAM stash dynamics assurance record

Statistical verification of the client-side stash — the probabilistic
property class the symbolic family (M1–M23) cannot express.

## Claim boundary (revised)

M24 is finite regression testing, not formal or statistical verification of
an overflow probability. Access targets cycle deterministically; leaf remaps
use OS randomness. There are no independent-trial confidence bounds.
Assertions establish properties only on executed traces.

Deduplication implies at most one stash entry per distinct absorbed identifier
(starting from an empty stash); target replacement preserves uniqueness and
eviction only removes entries. With a fixed universe of N identifiers this
provides a paper argument for at most N entries, not a machine-checked proof
or a useful small-stash tail bound. It does not cover arbitrary server inputs:
`access` accepts unknown identifiers and eviction retains unmapped blocks, so
successive paths can grow that universe. Deleted stale blocks also need care.

Classical Path ORAM bounds cannot simply be imported: this implementation
uses Z=4 and places each block only at its deepest shared level, retaining it
if that bucket is full instead of trying shallower eligible buckets. No
refinement to a published stash theorem has been established. The threshold
`N + 4*(height+1)` in the test is a regression ceiling for that workload only.

## Real bugs found and fixed

Driving the production code through the harness surfaced three genuine
defects that all prior symbolic milestones and unit tests had missed:

1. **Stale reads.** Tree buckets are shared between sibling leaves; a
   downloaded path can contain an outdated copy of a block that was since
   re-evicted elsewhere. `access()` absorbed duplicates without
   deduplication and `position()` returned the *first* match — surfacing a
   stale version. **Fix:** absorption drops tree copies whose id already
   exists in the stash, and within one path the deepest occurrence wins.
2. **Unbounded stash growth.** The same duplicated copies accumulated
   without bound: max observed **4692 blocks** on a 48-chunk/height-7 tree
   against an expected small constant. **Fix:** deduplication collapses the
   stash to its deterministic bound.
3. **Write-back clobbering.** Eviction rode the freshly *remapped* leaf
   while only the *old* leaf's path had been downloaded. Buckets below the
   LCA on the new side were overwritten without ever being read — silently
   destroying other chunks' stored blocks (manifesting as `None` reads).
   **Fix:** write-back rides the downloaded path; migration toward the
   remapped leaf happens lazily via `deepest_shared_level` placement on
   future accesses, the standard read-before-write scheme.

## Harness properties

Checks in the harness (at the checkpoints implemented by each test):
- Round-trip integrity: each chunk re-reads to its latest expected payload
  (content-checked, not just length) after thousands of mixed accesses.
- Bucket padding is checked by the measurement harness; the original M24 helper does not assert it.
- Unregister completeness: position-map entry, stash block, and future
  prepare-access all reflect removal.
- Duplicate-freedom: the stash never contains two blocks for one chunk.

Sampled regression ceiling:
- `stash_stays_bounded_over_five_thousand_accesses`: max stash over 5000
  mixed accesses on a height-7 / 48-chunk tree stays within the
  deterministic dedup bound (`chunks + 4·(height+1)`).

## Verification output

```text
m24 oram-stash-bounds gate: 4/4 statistical + invariant tests passed
```

Reproduce with:

```sh
./security/formal/run-oram-stash-bounds-tests.sh
# or directly:
cd libVELA/vela-crypto && cargo test --test oram_stash_bounds
```

Regression coverage for the three fixes lives in the harness itself
(duplicate-freedom guard runs inside every `full_cycle`) alongside the
pre-existing unit tests (`stash_size`, eviction distribution).

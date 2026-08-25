# M24 Path-ORAM stash dynamics assurance record

Statistical verification of the client-side stash — the probabilistic
property class the symbolic family (M1–M23) cannot express.

## Tool boundary

The classical Path ORAM guarantee ("the stash stays O(log N) with
overwhelming probability") is proved in the literature via a supermartingale
argument; a full EasyCrypt formalization is research-scale work. What ships
for M24 is:

1. **Direct statistical evidence** over the production `PathOram`
   implementation, driven through a faithful tree-structured fake server
   (buckets keyed by `(level, node)`, shared across sibling leaves exactly
   like the wire protocol).
2. **Hard deterministic invariants** asserted on every access of every run.
3. A **deterministic post-fix bound**: after the M24 deduplication fix, the
   stash holds at most one block per registered chunk plus path capacity.

hax is intentionally absent from this milestone: the interesting logic is
iterative and numeric (`deepest_shared_level` shifts, stash loops), which
hax 0.3.7's F* prelude cannot encode (i64/u64 ops are while-loop internals,
excluded from solver encoding) and ProVerif's nat has no arithmetic.

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

Hard invariants (every cycle of every test):
- Round-trip integrity: each chunk re-reads to its latest expected payload
  (content-checked, not just length) after thousands of mixed accesses.
- Bucket padding: every uploaded bucket is exactly `BUCKET_SIZE`.
- Unregister completeness: position-map entry, stash block, and future
  prepare-access all reflect removal.
- Duplicate-freedom: the stash never contains two blocks for one chunk.

Stochastic:
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

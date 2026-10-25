# iOS sync download/admission conformance (bounded exhaustive)

Status: **written, committed, not executed.** This host has no Swift toolchain,
so nothing in this increment has been compiled or run. The test is plain XCTest
and is picked up by the existing `VELATests` target (`iosVELA/project.yml`
includes `Tests` by directory, so no project change is needed). Hosted
confirmation must come from `.github/workflows/ios-app.yml`, which builds
`VelaCore.xcframework` and runs
`xcodebuild test -only-testing:VELATests`. Do not cite this file as passing
evidence until that run exists.

## Files

- `iosVELA/Tests/SyncAdmissionModelTests.swift` — reference model, exhaustive
  corpus, kernel boundary grid, four named witnesses.
- This README.

No other file changed. No Swift production code was edited, and no mutation is
committed.

## Reference model

Written from `libVELA/vela-sync-policy/src/lib.rs` (`plan_sync_epoch_match`,
`plan_chunk_download`, the integer epoch kernel) and claim INT-1 in
`security/assurance/01-security-claims.md`, plus the one iOS-level guard that
`SyncEngine.rejectRollback` documents. It is a plain Swift state machine; it
never calls the code under test to compute an expected value.

Per context `server ‖ account ‖ epoch` the model keeps a per-chunk floor (highest
admitted clock or `none`) and a whole-manifest floor (highest admitted clock in
that context). `none` is explicit first contact, never clock 0 — the Rust
`Option<i64>` baseline. A manifest carrying one chunk is decided in this order,
which is the order the real path applies:

1. the manifest epoch must be positive and exactly this device's authenticated
   epoch (iOS has no adoption on the download path);
2. the Swift manifest guard refuses a manifest whose highest clock is below the
   context's manifest floor (`SyncEngine.rejectRollback`, line 236);
3. the Swift per-chunk guard refuses a chunk below its recorded floor (same
   function, line 245);
4. the Rust kernel is entered with the raw integers plus the SWIFT-recorded
   baseline: it re-checks exact epoch agreement, requires the sealed header
   (legacy unsealed is refused), performs the real AEAD open (so a mislabelled
   clock fails), then applies `plan_chunk_download` (positive clock, `clock >=
   baseline`);
5. only on accept are floors set to `max(old, clock)`, and only then may
   content be persisted.

`AdmissionRefusal` therefore has four values — `epochMismatch`, `rollback`
(the Swift guard), `unreadable` (AEAD failure or nonpositive clock from the
kernel), `legacy` (unsealed blob) — and the test compares the refusal *reason*,
not only the boolean.

## Universe and alphabet

One server (`https://vault.example`), two accounts (`account-a`, `account-b`),
two authenticated epochs for `account-a` (1 and 2), two chunk ids
(`vault-data-000000`, `vault-data-000001`), clocks 0…3. Three contexts are
constructed: `a@1`, `b@1`, `a@2`. Every sealed fixture is generated for both
epoch 1 and epoch 2, because an epoch-2 seal binds the epoch as well as
`chunk_id ‖ clock`.

The 10-command alphabet models what a stale or hostile server can return:

| # | command | shape | model expectation |
|---|---------|-------|-------------------|
| 1 | `chunk0-clock0-sealed` | correctly sealed at clock 0 | refused (nonpositive clock) |
| 2 | `chunk0-clock2-sealed` | correctly sealed at clock 2 | both |
| 3 | `chunk0-clock3-sealed` | correctly sealed at clock 3 | admitted |
| 4 | `chunk1-clock2-sealed` | second chunk id at clock 2 (equal-epoch offer) | both |
| 5 | `chunk0-served2-sealed1` | sealed for clock 1, served as clock 2 (wrong AAD) | refused (AEAD) |
| 6 | `chunk0-clock2-unsealed` | blob without the `VAE1` header (pre-C-2 shape) | refused (legacy) |
| 7 | `epoch-offer-next-bound-capsule` | manifest epoch `local+1`, capsule bound | refused (epoch) |
| 8 | `epoch-offer-next-unbound-capsule` | manifest epoch `local+1`, no capsule | refused (epoch) |
| 9 | `epoch-offer-jump-bound-capsule` | manifest epoch `local+2`, capsule bound | refused (epoch) |
| 10 | `account-switch` | advance `a@1 → b@1 → a@2 → a@1` | no decision |

Replay is not a separate command: re-serving a clock the context already
admitted is exactly command 2 or 3 after an earlier admission, and the corpus
enumerates both the equal-clock (`max(old, clock)`) and the older-clock shapes.
Commands 7 and 8 exist to show that a capsule-bound and an unbound offer are
indistinguishable on `/vault/sync` — iOS does not transmit or consume an
adoption capsule there.

## Exploration

Every non-empty command sequence of length 1…3 is enumerated (constant, no
randomness, no environment variable):

| depth | traces | command applications |
|-------|--------|----------------------|
| 1 | 10 | 10 |
| 2 | 10² = 100 | 200 |
| 3 | 10³ = 1000 | 3000 |
| total | **1110** | **3210** |

321 of the 3210 applications are account switches (1 + 2·10 + 3·100), so the
corpus makes **2889** real `SyncEngine.sync` calls. These three counts are
asserted, so an accidental change to the alphabet or depth is visible.

Each trace starts clean: `SyncEngine.clearBaselines()` and `VaultRepository.reset()`,
then the floors are asserted to be `none` for all `3 × (2 chunks + 1 manifest)`
entries before the first step. After **every** step the test compares, against
the model:

- the accept/refuse decision **and its reason**;
- for an admitted download, that the returned store contains exactly the marker
  item the served chunk carried, and that `VaultRepository.load` returns the
  same store (the bytes reached disk);
- for a refused download, that `VaultRepository.load` is unchanged
  (checked against the real repository, and separately in the named witness with
  a non-empty local vault);
- all six per-chunk floors and all three manifest floors (exact equality with
  the model, plus "never lower, never disappear" against the previous step);
- that no epoch was adopted: the three engines keep the epochs they were built
  with and the offered epoch's namespace stays untouched.

Constant work is bounded by the fixtures: 18 pre-sealed blobs (9 commands × 2
epochs; 16 `encryptVaultChunk` calls plus 2 fixed legacy blobs) and one
URLSession per test. No wall-clock or network access. The dominant cost is the
2889 syncs (roughly 4.8k in-process `URLProtocol` requests plus ~1.6k vault
encryptions and ~29k `UserDefaults` floor reads); the estimate is 15–40 s on the
CI simulator. If CI is materially slower than that, reduce the alphabet rather
than dropping the count assertions.

## Non-vacuity

- Commands 2 and 4 are asserted to be **both** admitted and refused somewhere
  (clock 2 is refused once clock 3 has been admitted in that context, including
  via the manifest floor after `chunk1`).
- Commands 1, 5, 6, 7, 8, 9 are asserted to be refused at least once and never
  admitted.
- Command 3 is asserted to be admitted at least once (and, by the alphabet's
  clock ceiling, never refused).
- Command 10 is asserted to produce no decision and to occur.
- Each of the four refusal reasons occurs at least once.
- A cross-context witness is required: some trace must admit a revision in one
  namespace that another namespace's own floor would refuse. Trace
  `chunk0-clock3 → account-switch → chunk0-clock2` supplies it (`a@1` floor 3,
  `b@1` empty), so one account's floors demonstrably do not gate another's.
- The namespace-separation check is also structural: after `chunk0-clock3` (in
  `a@1`) the corpus reaches `b@1` and `a@2` and requires their floors to still be
  `none`.

## Second test: kernel boundary grid

`testAdmissionKernelBoundaryGridMatchesIndependentPredicate` calls
`VelaCoreFFI.decryptVaultChunkAdmitted` directly (the narrowest real Swift
function that carries the Rust decision) over clocks `{-1, 0, 1, 2, 5}`, recorded
baselines `{none, 0, 1, 2, 5, 7}`, correct vs relabelled AAD, and epoch pairs
`(1,1) (1,2) (2,1) (0,0) (-1,1) (1,0)` — **360** kernel calls. It compares
against a predicate written independently in the test (`positive epochs, exact
agreement, positive clock, not older than the baseline, AAD binding`) and
asserts the permit carries the served clock and the sealed plaintext. This is
the only test here that reaches the Rust kernel's own rollback branch; see the
coverage note below.

## Named witnesses

- `testEpochJumpOfferIsRefusedAndNoNamespaceMoves` — `a@1` offered epoch 3 with a
  capsule: `epochMismatch`, no floors, no vault, namespaces untouched.
- `testRollbackRefusedFloorNeverDecreasesAndReplayStaysAdmitted` — admit clock 3,
  serve clock 2 sealed for its own clock: `rollback`, floor stays 3, store
  unchanged; then the equal-clock replay is admitted and idempotent.
- `testRefusedDownloadsLeaveNonEmptyLocalVaultIntact` — a real non-empty local
  vault survives a clock-0 refusal, a wrong-AAD refusal and an unsealed refusal
  unchanged, and no floor is recorded.

## Real functions exercised

`SyncEngine.sync`; `SyncEngine.rejectRollback` (via `sync`); the engine's
`baselineContext`; `SyncEngine.recordAdmitted`, `recordedSeenClock`,
`recordedManifestClock` (via `sync` and the direct floor reads);
`SyncEngine.clearBaselines`; `VelaClient.syncManifest` and `getChunk` (over a
`URLProtocol` stub, the same pattern as `Phase4Tests`); the whole Rust admission
bridge behind `VelaCoreFFI.decryptVaultChunkAdmittedOrThrow` /
`decryptVaultChunkAdmitted` (epoch agreement, sealed-header gate, AEAD open,
`plan_chunk_download`); `VelaCoreFFI.encryptVaultChunk` for fixtures;
`VaultMerge.mergeStores`; `VaultRepository.save`, `load`, `reset`; the App Group
`UserDefaults` floor store.

## Not covered

- **Not executed.** Compilation, runtime and the exact counts above are
  expectations computed by hand; CI has not confirmed them. If
  `XCTAssertEqual(traces.count, 1110)`, `stepCount == 3210` or `syncCount == 2889`
  fails, the harness (alphabet/depth), not the product, is what drifted.
- No proof is produced or re-run. This is bounded executable conformance against
  a hand-written model, not the F★/Rust proofs and not a full-system claim.
- The push path is never entered: every manifest in the corpus carries exactly
  one `vault-data-*` chunk and the merge of the (empty) local store with that
  document equals the document, so `merged == remoteStore` and `sync` does not
  upload. Upload clocks, chunk deletion, `splitUtf8`, the legacy `vault`/
  `vault-main` migration layouts and `activateRichSchema` are untested.
- The corpus passes `localStore: VaultStore(items: [])`, so merge conflicts,
  tombstones and multi-item unions are out of scope; a separate witness only
  checks that a non-empty on-disk vault survives refusals.
- One chunk per manifest. Swapping a chunk id inside a multi-chunk document,
  concatenation/decode failures and duplicate chunk ids are untested here
  (`Phase4Tests.testFailedDecodeDoesNotAdvanceBaseline` covers the decode case).
- Clocks 0…3 and epochs 1…3 only. Signed extremes and the whole i64 boundary
  grid are covered by the Rust tests, not by this file.
- Epoch adoption is not reachable from the iOS download path and is not tested:
  `plan_epoch_adoption`/`plan_epoch_decision` have no export in
  `libVELA/vela-apple-bridge/src/lib.rs`; iOS adopts epochs out of band through
  enrollment/recovery (`AccountViewModel`, `VaultViewModel.adoptVault`), which
  this file does not drive. The capsule-bound offers only show that the
  `/vault/sync` path ignores the capsule; capsule binding itself is untested
  here.
- Account switching is a test construct (a second engine with a different
  `accountID`). The app holds one account per install today; multi-account
  sign-out and `clearBaselines()` clearing *all* contexts are not exercised
  mid-trace (`SyncEngine.clearBaselines` documentation, lines 207–224).
- Concurrency, the `NSLock` writer guarantee, cross-process App Group writers,
  crash between `save` and `recordAdmitted`, HTTPS/TLS, real server behaviour,
  SSE, Keychain/App Attest, RMS storage, and the AEAD/KDF primitives
  (AES/XChaCha, HKDF) are outside this file.
- The Rust kernel's rollback branch is unreachable through `sync` because
  `rejectRollback` pre-checks the same floors first; the boundary grid reaches
  it directly, but the composition "Swift gate weakened, Rust refuses" is not
  executed.

## Proposed mutation (not committed)

One-line weakening in `iOSVELA/Shared/SyncEngine.swift` line 186:

```swift
// current
for entry in chunks where entry.clock > (recorded[entry.id] ?? 0) {
// mutation
for entry in chunks where entry.clock < (recorded[entry.id] ?? 0) {
```

With `<`, a missing entry is treated as 0 and `clock < 0` is false, so the
per-chunk floor is **never recorded** (the manifest floor on line 199 still is,
because it uses `max`). The first accepted download is the second step of trace
`chunk0-clock0-sealed → chunk0-clock2-sealed`; after it, the model expects chunk
floor 2 and the real store reports `none`, so
`XCTAssertEqual(current, snapshot(model: model), "… recorded floors diverged …")`
fails. Once the chunk floor is gone, `rejectRollback` and the FFI baseline see
`nil`, so a later trace (for example `chunk0-clock2-sealed →
chunk0-clock3-sealed → chunk0-clock2-sealed`) has the real path admit a clock
the model refuses — `XCTAssertEqual(observed, expected, "… decision diverged …")`
fails as well. Both a "floor must equal the highest admitted clock" and a
"rollback never admitted" assertion therefore catch this weakening.

## Suspected bugs / divergences

No Swift behaviour was found that admits a rollback, lowers a floor, adopts an
epoch jump, or lets one context's floors gate another's. Three deliberate
differences are worth recording rather than encoding as bugs:

1. **iOS is stricter than INT-1 on the download path.** `sync` refuses a
   manifest at `local+1` exactly like one at `local+2`
   (`SyncEngine.swift:295-301`); adoption happens only out of band. The model
   encodes this stronger rule, so the corpus checks "nothing is adopted", not
   the Rust ladder's "at most `local+1` with a bound capsule". `plan_epoch_adoption`
   has no Apple FFI export, so the ladder cannot be exercised from iOS at all.
2. **The Swift manifest floor is stricter than the per-chunk Rust predicate.**
   A manifest whose highest clock is below the context's recorded manifest clock
   is refused even if each listed chunk is at or above its own floor
   (`SyncEngine.swift:233-249`). This is fail-closed and the model treats it as
   part of the iOS guard; it means a single chunk's *manifest* entry can gate
   another chunk *within the same context* (not across accounts). If the parent
   wants the model to be purely the Rust predicate, these refusals must be
   reported separately instead of asserted as accepts.
3. **The Rust rollback branch is masked.** In `sync` the FFI receives
   `lastSeenLamport` from the same `UserDefaults` that `rejectRollback` just
   checked, so a rollback is always refused by the Swift guard first. This is
   defence in depth, not a defect, but it means the iOS integration path
   exercises the Rust kernel's *accept*, *epoch-mismatch*, *AAD* and
   *legacy* decisions while its *rollback* decision is exercised only by the
   direct kernel grid test.

One coverage observation, not a bug: `VelaClient.getChunk` returns
`X-Lamport-Clock` and `X-Chunk-Version`, but `sync` ignores both and admits at
the manifest's `lamport_clock` (`SyncEngine.swift:308`). Because the clock is
bound into the AAD, a disagreement can only cause a refusal, never a wrong
admission. The test does not vary the response header away from the manifest
clock.

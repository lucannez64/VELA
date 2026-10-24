# Sync policy and universal chunk-admission proof

`verify-fstar.sh` freshly extracts and checks the historical 11 Rust
postconditions, then invokes `verify-fstar-chunk.sh` in a separate F★ process.
The second invocation checks 20 handwritten lemmas against that same extracted
`plan_chunk_download`, with caching disabled for the supplied modules.

For every input and permit, `Accept(permit)` is equivalent to:

- the caller-supplied AAD and epoch-positivity flags hold;
- the server clock is at least 1;
- the baseline is absent, or the server clock is at least that baseline;
- the permit carries exactly the server clock.

The module separately states this predicate over raw clocks/options. It also
checks rejection, permit uniqueness, arbitrary baseline floors, equal-clock
redelivery, signed-clock extremes and concrete accept/reject witnesses.
`None` and `Some(0)` produce the same decisions because clocks must be positive;
they remain distinct observations. Negative baselines do not bypass the
positive-clock requirement. A false epoch flag rejects even the largest clock.
The permit contains a clock, not an integer epoch.

These are conditional kernel properties. This module neither derives the AAD
flag from ciphertext nor the epoch flag from an integer. It does not prove
chunk/account/server context binding, actual authenticated opening, baseline
storage, native/desktop callers or whole-system rollback protection. In
particular, a caller supplying an incorrect flag remains outside this theorem.
The mobile runtime and focused integer-epoch kernel are separate work awaiting
integration. Production Rust decisions are unchanged by this increment.

Run through `vela-heavy` with pinned hax 0.3.7, F★ 2025.10.06 and Z3 4.13.3;
see the client-recovery policy README for tool setup. The verifier logs version,
module hashes and argv. Its source/count guard rejects local proof escapes and
source options (allowing only exact hax-generated fuel/budget boilerplate);
the guard is not a soundness certificate. Imported models, extraction and
proof tools remain trusted. The 20 handwritten lemmas add zero Rust
postconditions to the 245-contract corpus. Evidence and run provenance are in
`security/assurance/proof-logs/current/f5-universal-chunk-admission/`.

## Mobile and integer-epoch increment

# vela-sync-policy — scope and boundary

This crate owns the pure accept/refuse decisions for the vault sync boundary.
Mobile and desktop callers turn authenticated observations into facts and act
only on the permits returned here. I/O, key derivation, AEAD opening, network
parsing and storage remain outside.

## What is checked

- `plan_chunk_download` (and its spec function `chunk_download_decision_matches_spec`)
  is extracted and checked by `verify-fstar.sh`. It rejects a chunk whose
  server Lamport clock is older than the per-chunk clock this device recorded,
  rejects a nonpositive clock, and requires the caller to confirm that the
  epoch-bound AAD actually authenticated.
- `plan_sync_epoch_match` is the focused F-5 mobile kernel checked by
  `verify-fstar-epoch.sh` into `proofs/fstar/extraction-epoch/`. It compares the
  manifest epoch and this device's authenticated epoch as **integers** and
  returns true only when both are positive and exactly equal. Mobile clients do
  not adopt a rotation automatically, so a mismatch refuses the download.
- `proofs/fstar/epoch-lemmas/Vela_sync_policy_epoch_lemmas.fst` states the F-5
  property *parametrically*, not as three examples:
  `accepted => both epochs positive and equal`, the converse
  `positive+equal => accepted`, `decision == independently stated predicate`,
  and the explicit refusal direction. The predicate in that file is written out
  rather than defined by calling the extracted function, so the lemmas are not
  circular. Both modules are checked in the same `fstar.exe` invocation and end
  with `All verification conditions discharged successfully`.

The two artifact directories are intentionally separate. `verify-fstar.sh`
still regenerates exactly the historical selected set (then runs
`verify-fstar-epoch.sh`), so the global proof manifest and correspondence
inventory are unchanged by the F-5 increment.

## What the F-5 integration does

The Android and Apple production sync download paths now call
`plan_chunk_download` through a narrow bridge entry point. That entry point:

1. compares the raw server/local epoch integers through `plan_sync_epoch_match`;
2. requires the self-describing sealed header (`aead::is_sealed`) and performs
   the real `open_fleet_chunk` AEAD open; and
3. only after a successful open, constructs `ChunkDownloadFacts` with
   `aad_binding_verified: true` and applies the verified rollback decision.

Why the sealed-header gate exists: `open_fleet_chunk` deliberately keeps the
pre-C-2 wire shape readable at epoch 1 for fleet migration, and that shape
includes **unsealed** `aead::encrypt` blobs, which authenticate neither the
chunk id nor the revision. A caller-supplied clock would then be accepted for
any ciphertext, making the rollback decision meaningless. The admitted path
therefore refuses unsealed blobs. Sealed epoch-1 blobs bind `chunk_id ‖
lamport_clock`; sealed epoch-2+ blobs also bind the account epoch. Pre-C-2
unsealed data must be re-sealed through an explicit migration path (trusted
client, current epoch); that path is not implemented in this increment, so such
a blob now fails the mobile sync closed rather than being admitted, and carries
**no** claim of rollback protection while it is still unsealed/clock-0.

`aad_binding_verified` is therefore a fact about successful Rust decryption,
never a JSON/Swift/Kotlin boolean supplied by the caller. Plaintext leaves the
bridge only on `Accept`, and the response carries the admitted Lamport clock so
callers baseline exactly what the policy accepted.

## Caller obligations (Android / Apple)

- Baselines are namespaced by `(normalized server, authenticated account, key
  epoch)`. A missing entry is an explicit first contact; a new epoch (adoption)
  starts a fresh context because the server's counters restart. Changing
  servers/accounts does not inherit a baseline, and switching back preserves
  the context's own record.
- Baselines are advanced only **after** the admitted plaintext was decoded,
  merged and durably persisted locally (and, for uploads, after every write
  succeeded). A failed/partial batch records nothing.
- The only deliberate reset is sign-out / local-security reset, which clears
  baselines. Routine `updateServer` for the same server does not.
- Unreadable baseline JSON fails closed: sync refuses and points at the
  explicit reset. An unrelated settings write keeps the original bytes so it
  cannot launder corruption into an empty, fail-open baseline.
- Android serializes the whole settings read-modify-write under one lock and
  uses a synchronous `commit`, so a concurrent token refresh and baseline
  advance cannot lose each other. iOS uses an `NSLock` around its baseline
  read-modify-write within the process; cross-process app/extension writes are
  documented as unsynchronized (a missed advance, not a lowered baseline).

The lower-level `decrypt_vault_chunk_*` entry points remain for unit, legacy and
non-sync callers. Calling one of those is **not** an admission decision and
must not be treated as one.

## Remaining open obligations

- Rust JSON envelope parsing/serialization, JNI and C buffer handling, and the
  exact Swift/Kotlin wrappers are unverified glue. The Apple/Swift caller could
  not be compiled or executed on this Linux host (no Swift toolchain), so its
  tests are written but unrun here.
- The native callers' ordering (fetch → admit → decode → merge → persist →
  record baseline) is tested at the unit level but not proved; crash atomicity
  between local persistence and baseline commit is open (a crash in between
  re-admits a revision once, it cannot lower a baseline).
- iOS cross-process baseline writes (app vs. share extension) are not
  serialized; App Group `UserDefaults` offers no transaction across processes.
- Pre-upgrade baseline keys are not migrated into a namespace (they cannot be
  attributed to a server/account/epoch after the fact), so the first sync after
  upgrading is an explicit first contact: one possible replay window for old
  history, rather than reusing a possibly foreign context's clock.
- The store's synchronous commit makes lost updates within a process
  impossible, but `SharedPreferences`/`EncryptedSharedPreferences` durability
  beyond `commit()` is an OS guarantee taken as trusted.
- The existing epoch-adoption path still receives
  `EpochAdoptionFacts::server_epoch_is_next` from its caller. No new automatic
  adoption feature was added here, and that caller-supplied transition flag
  remains outside the verified decision for clients that do adopt.
- Imported primitives, the proof tools, the OS and the compiler are trusted per
  `security/assurance/09-target-contract.md`.

These are implementation-correspondence gaps, not claims that the checked
policy itself is unsound.

# 8. Formalization obligations and current boundary

**Full-system formalization is not complete.** This document separates checked
results from remaining obligations. Decision proofs and a symbolic journal
model do not establish the entire implementation's security.

## Selected trusted boundary

The maintainer has selected OS/compiler and primitive-security trust. The
[target contract](09-target-contract.md) defines the resulting application and
construction obligations. Verifying external primitive implementations and OS/
compiler internals is excluded; VELA's hybrid combiners, encodings, handler
logic and native caller behavior remain in scope. This selection does not
turn any open obligation below into a proved result.

## Additional checked results

- **Ten production transaction/recovery postconditions.** Desktop sharing now
  calls `initial_acceptance_is_authorized`, `next_store_generation` and
  `recovery_should_apply` directly. Seven negative theorems cover stale
  generations, pending-journal overwrite, generation overflow, local-edit
  overwrite, tombstoned-item resurrection, existing-pin restart and missing
  payloads. These prove decisions over supplied observations, not I/O.
- **The actual share-fact constructor.** A new F* postcondition specifies every
  `share_envelope::admission_facts` output, including failed-open cases,
  account/key/lineage comparisons and revision fields. It is conditional on
  the `OpenedShare` observation and independent context; opening, parsing,
  crypto correctness and context origins remain unproved. A local defined
  String view is manually trusted; see the
  [proof boundary](../../libVELA/vela-crypto/proofs/fstar/README.md).
- **Seven Tamarin journal properties.** M28 checks matching content/pins on
  opening, journal-before-vault writes, vault-before-cleanup, snapshot-generation
  provenance, one application per transaction, strict revision advance at each
  commit, and a crash/recovery witness. Atomic durable single-file replacement
  is assumed. Product-state rules write the two files separately; no atomic
  two-file write is assumed. Crashes preserve durable state; retained stale
  snapshots overapproximate volatile behavior. Local edits/deletions and
  independent processes are outside M28.
- **Additional production composition and parsing.** The actual
  `plan_observed_share` composition proves raw decoded-field authorization,
  including rejection, pin matching and permit revision. The real prefix reader
  uses a checked exact-prefix/suffix function. The hybrid signature path uses a
  checked AND gate with two rejection theorems; its permit revision getter is
  also checked. These are conditional contracts, not complete parser/crypto/I/O
  verification.
- **Composed M29 model.** Eleven lemmas now pass in one system joining dual
  signature checks, immutable pin frames, separate durable writes and crash
  recovery. Provenance is retained if either signing component remains
  unrevealed, with explicit honest-key premises. See
  [the mapping](../formal/signed-share-commit-correspondence.md).
- **Reduced assumption boundary.** Structural Rust matches replaced the 18
  opaque derived-enum equality uses. Fresh checking of all eight policy crates
  succeeded with zero local assume val declarations. The inventory now has
  **119 explicit postconditions / 122 selected functions** in eleven Rust modules,
  plus one defined String compatibility model. Three selected functions have
  no explicit ensures. Imported library assumptions and proof tools remain
  trusted; the drift checker is not a proof checker.

[Current evidence](proof-logs/current/trusted-boundary/README.md) supersedes
prior extraction snapshots for all eight policy crates. CI includes the new
checks. The [hosted refinement job](proof-logs/current/hosted-refinement-40002230354/README.md)
passed on `b27dcd6`; the complete security workflow remains pending.

The I/O-contract review also found and fixed an uncertain-write recovery gap:
readable pending metadata now receives a successful durability re-arm before
vault application. Its regression fails on the previous ordering and passes
with the fix. This does not close the concrete I/O refinement obligation.

A [written hybrid-signature EUF-CMA reduction](10-signature-reduction.md) now
specifies the exact byte-message game, a lossless projection to either
component, and disclosure of the other key. It is a mathematical argument
for review; its computational game and simulation are not machine-checked.

Five freshly extracted wire contracts prove exact big-endian decoding, byte
decomposition, encoding round-trip and injectivity for all u64 values. The
production share-envelope integer writer/reader use this checked codec. This
does not prove the entire parser or variable-length field framing.

## Remaining obligations for the six requested areas

| Area | Status | Required to close |
|---|---|---|
| F-1: handler facts | Partial | Prove parser/authenticated-open contracts and independent context origins; cover SQL, token, epoch, enrollment and recovery fact construction across all handlers |
| F-2: state transitions | Partial | Machine-check concrete handler/database transitions against protocol transitions, including exceptions, cancellation and concurrency |
| F-3: persistence/recovery | Partial: M28 and composed M29 | Prove the actual journal implementation refines M28; formalize collection equality and filesystem outcomes; compose local edits/deletions and RMS migration; cover or explicitly exclude independent processes |
| F-4: construction security | Partial: AND gate and ideal-signature composition | Define computational games and prove reductions for VELA hybrid KEM/signatures, framing, share tags, possession proofs and KDFs under named primitive assumptions; verify application randomness/error/erasure handling. Primitive internals and leakage resistance are trusted under the selected boundary |
| F-5: native clients/composition | Open beyond scoped tests/models | Verify Kotlin/Swift callers, persistence and FFI; formalize enrollment UI trust; compose recovery, enrollment, sync, sharing and revocation in one argument |
| F-6: trusted base | Partial | Maintain zero local extraction assumptions and review imported model contracts; verify/review std/hax model correspondence and the String view; retain extraction/compiler correctness explicitly as trusted under the chosen boundary; review solver/library/OS interface assumptions; reproduce in CI and obtain independent review |

Every complete scoped proof must still choose a logic/kernel, machine model
and interface to physical execution. An assumed OS operation in a model is
not a proof that a deployed filesystem implements that operation.

## Stronger journal goals not proved

An exploratory run added all-pairs `a_generation_commits_at_most_once` and
`committed_pins_never_decrease` goals. Search was stopped without completing and without a proof verdict. These goals are not counted
among the seven verified M28 results or included in its CI success set. Strict
advance at an individual commit is proved; the stronger unbounded all-pairs
theorem was not established. The explicitly named unfinished log is retained.

A matching hash, finite tests, unproved annotation, ideal primitive, new axiom
or mocked database cannot substitute for these obligations. No unsupported
computational reduction, full Rust/Kotlin/Swift refinement or whole-system
completion claim is supplied here.

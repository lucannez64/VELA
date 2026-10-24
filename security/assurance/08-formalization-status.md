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
- **Ten Tamarin journal properties.** M28 checks matching content/pins on
  opening, journal-before-vault writes, vault-before-cleanup, snapshot-generation
  provenance, one application per transaction, strict revision advance at each
  commit, a crash/recovery witness, the exact all-pairs goals
  `committed_pins_never_decrease` and `a_generation_commits_at_most_once`, and
  a two-successive-commit witness. The all-pairs goals are stated over emitted
  actions only and are nonvacuous: the witness makes both antecedents
  reachable. Their proofs use a conservative `Chain` ghost fact, described
  below. F★ checks lifting/projection between typed single-slot encodings;
  their bridge to actual Tamarin traces remains unproved. Atomic durable
  single-file replacement is assumed. Product-state rules write the two files
  separately; no atomic two-file write is assumed. Crashes preserve durable
  state; retained stale snapshots overapproximate volatile behavior. Local
  edits/deletions and independent processes are outside M28. The journal runner
  also rejects lemma/restriction atoms whose fact name or arity is not emitted
  in a rule action list (`check-action-atoms.py`); this is a source guard
  against vacuity, not a soundness certificate.
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
  **231 explicit postconditions / 238 selected functions** in eleven Rust modules,
  plus defined String and Vec compatibility models. Seven selected functions have
  no explicit ensures. Imported library assumptions and proof tools remain
  trusted; the drift checker is not a proof checker.

The enrollment ceremony now computes every policy fact through five pure
constructors (`open_facts`, `claim_facts`, `inspect_facts`, `completion_facts`,
`result_facts`) with hax postconditions, plus fifteen negative theorems. The
handlers read grant/claim presence, decoded key lengths, session/grant identity
equality, the opener's `revoked` column, the primary/collector signature result,
and the account epoch/rotation state. These twenty entry points are listed in
`serverVELA/vela-enrollment-policy/verify-fstar.sh` and were extracted and checked
in the [successful hosted refinement job](https://github.com/lucannez64/VELA/actions/runs/40039992434/job/120708563220)
on fbe35c0. That hosted inventory was 152 postconditions / 159 selected functions.
The exact CI extraction and logs are retained in the
[enrollment evidence](proof-logs/current/hosted-enrollment-40039992434/README.md). The observations themselves (SQL queries, store calls, signature
verifier, session ids) remain unverified glue; `claim_key_source: StoredClaim`
records the structural fact that the handler never accepts claim keys from the
request body.

[Current evidence](proof-logs/current/trusted-boundary/README.md) supersedes
prior extraction snapshots for all eight policy crates. CI includes the new
checks. The [hosted refinement job](proof-logs/current/hosted-refinement-40002230354/README.md)
passed on `b27dcd6`, and the [complete security workflow](https://github.com/lucannez64/VELA/actions/runs/40008926193)
passed on `e690dfc`. The parser/transcript and new enrollment contracts also passed hosted
refinement on fbe35c0. That full workflow failed before CryptoVerif ran because
of its runner permission error; a successful refinement job is not a successful
whole-workflow result.
The subsequent [complete security workflow](https://github.com/lucannez64/VELA/actions/runs/40041986647)
passed on 40c9f30 for that earlier 152-postcondition/pre-correction-model snapshot.
The strengthened computational games and the 21 new recovery contracts require
their own hosted reproduction.

The I/O-contract review also found and fixed an uncertain-write recovery gap:
readable pending metadata now receives a successful durability re-arm before
vault application. Its regression fails on the previous ordering and passes
with the fix. This does not close the concrete I/O refinement obligation.

A [written hybrid-signature EUF-CMA reduction](10-signature-reduction.md) now
specifies the exact byte-message game, a lossless projection to either
component, and disclosure of the other key. Its computational byte-message games now have CryptoVerif proofs under the
assumptions in the model README; complete Rust wrapper and game-composition
correspondence remains open.

Five freshly extracted wire contracts prove exact big-endian decoding, byte
decomposition, encoding round-trip and injectivity for all u64 values. The
production share-envelope integer writer/reader use this checked codec. This
is extended by the [concrete byte-frame refinement](11-parser-refinement.md),
including LP bounds, grouped cursor operations and exact frame field values.
The [received-byte transcript increment](12-authenticated-transcript.md) adds
checked body slicing and exact domain concatenation, used by the production
sender and opener. UTF-8/object conversion, encoder inverse and complete
authenticated-opening composition remain unproved.

The production byte parser now refines a functional VSE2 grammar for all input
slices. Cursor contracts cover fixed/LP fields and atomic grouped reads. Three
accessor kernels preserve opened fields/bytes; Rust module privacy and two
compile-fail checks prevent safe external construction/mutation of opened
observations. These results do not establish crypto-wrapper correctness or
context origins; see [the exact boundary](11-parser-refinement.md).

## Computational proof of the hybrid KEM combiner

CryptoVerif 2.12 proves idealized v2-combiner IND-CCA2 games, manually
mapped to `kem.rs`: from uniform prime-order GDH with ML-KEM correctness and its secret key
disclosed, and from ML-KEM IND-CCA2 plus the library collision bounds with the
DH secret exponent disclosed. Both use a random oracle. Together they give
the scoped model-level surviving-component claim (COMP-5), rather than a
complete theorem for the concrete X25519 construction. The legacy v1
combiner does not prove in the first game, as expected. A third game proves
`seal_share` IND-CCA2 as public-key encryption from an IND-CCA2 KEM and an
IND-CPA + INT-CTXT AEAD (KEM-DEM). Two more games machine-check the hybrid
signature reduction: the AND signature is EUF-CMA under the surviving ML-DSA-87
or Ed25519 assumption, with the other secret key leaked, under the documented
independent-key and fixed-length encoding assumptions in the model README. The X25519
cofactor, correspondence to the actual clamped scalar distribution, SHA-256 step and multi-user
security are open, as listed in
[the model README](../formal/cryptoverif/README.md). CI expects six proved models and one explicitly unproved legacy baseline;
the repaired runner rejects process errors/timeouts and missing verdicts.

The nonuniform GDH companion now exposes collision and rerandomization losses
in a separate checked game. It assumes an unspecified nonuniform exponent
distribution; the conditional HPKE/Curve25519 constants are documented, not a
machine proof of the Rust clamp, subgroup handling or wire encoding. Its full
seven-model gate passed locally and in the [350cd57 hosted workflow](proof-logs/current/hosted-350cd57/README.md).
The [collision-side-condition note](proof-logs/current/x25519-nonuniform-gdh/COLLISION-SIDE-CONDITIONS.md)
separates pre-challenge freshness charges from post-challenge GDH queries; it
is a paper explanation alongside the retained tool debug trace.

## Recovery observation increment

The [recovery fact refinement](13-recovery-fact-refinement.md) adds 21 locally
checked postconditions, bringing recovery to 42 and the corpus to 173/180.
Initiation, credential-update and share-release constructors specify every
field from supplied observations; an epoch helper preserves the existing
missing/non-positive-to-initial normalization. This does not prove epoch freshness.
The handlers call the constructors, and challenge insertion now uses atomic
insert-if-absent so a stale freshness observation cannot overwrite a winner.
A real-store regression covers that interleaving; it is not an I/O refinement
proof. SQL/store/WebAuthn origins, early-return paths and complete state effects
remain open. [Hosted CI on `b8221e7`](https://github.com/lucannez64/VELA/actions/runs/40046015273)
reproduced all 173 postconditions, including these 21 recovery additions.

## Web-session observation increment

The [web-session refinement](14-session-observation-refinement.md) adds ten
locally checked contracts: constructors compute account bindings from optional
u128 identities, enforce grant nonce length, preserve the other observations,
and compose with the existing policies. Six rejection theorems cover absent
accounts, cross-account exchange, wrong nonce length and unsuccessful challenge/
signature observations. Handlers call the compositions and use the actual
verifier Result. The corpus is now 183/190; source decoding, actual SQL/store
semantics and complete handler traces remain open. Hosted reproduction of this
increment passed in the [350cd57 hosted workflow](proof-logs/current/hosted-350cd57/README.md).

## Possession and enrollment observation increment

The [remaining recovery constructors](15-recovery-possession-enrollment.md)
added 29 checked contracts: recovery reached 71 and the corpus 212/219.
The [enrollment preflight increment](16-enrollment-preflight.md) adds eight
contracts, initially bringing recovery to 79 and the corpus to 220/227.
Eleven additional independent ordering/readiness contracts now bring recovery
to 90 and the corpus to 231/238. The
parent strengthened enrollment to derive key validity from actual decoded
lengths (1600/2624) inside the verified constructor. Possession state insertion
uses atomic insert-if-absent, and empty commitments fail unavailable. Fresh
F★ checking and handler regressions pass locally. The observation snapshot was
reproduced on `350cd57`; the later preflight/ordering increment remains pending.
Grant store-key user binding, decoders, verifiers, storage effects, restoration
and complete handler traces remain open.

## Remaining obligations for the six requested areas

| Area | Status | Required to close |
|---|---|---|
| F-1: handler facts | Partial: hosted enrollment/recovery baseline; local web-session and additional recovery constructors | Maintain the checked contracts; verify the observation producers (SQL rows, store lookups, signature verifier, session ids) themselves; complete UTF-8/object and authenticated-open composition after the checked byte-frame parser; prove independent context origins; cover remaining token, epoch, recovery and handler fact construction |
| F-2: state transitions | Partial: preflight ordering/readiness checked against an independent specification | Machine-check concrete handler/database transitions against protocol transitions, including exceptions, cancellation and concurrency |
| F-3: persistence/recovery | Partial: M28 and composed M29 | Prove the actual journal implementation refines M28; formalize collection equality and filesystem outcomes; compose local edits/deletions and RMS migration; cover or explicitly exclude independent processes |
| F-4: construction security | Partial: CryptoVerif proofs for idealized v2 KEM games, modular KEM-DEM and AND-signature games under the explicit assumptions | Close the combiner gaps listed in `security/formal/cryptoverif/README.md` (concrete X25519 clamping/cofactor/encoding correspondence after conditional nonuniform distribution accounting, SHA-256 step, quantum-query and multi-user composition; KEM-DEM is proved modularly); computational games and reductions for envelope framing, share tags, possession proofs and KDFs under named primitive assumptions; verify application randomness/error/erasure handling. Primitive internals and leakage resistance are trusted under the selected boundary |
| F-5: native clients/composition | Open beyond scoped tests/models | Verify Kotlin/Swift callers, persistence and FFI; formalize enrollment UI trust; compose recovery, enrollment, sync, sharing and revocation in one argument |
| F-6: trusted base | Partial | Maintain zero local extraction assumptions and review imported model contracts; verify/review std/hax model correspondence and the String/Vec models; retain extraction/compiler correctness explicitly as trusted under the chosen boundary; review solver/library/OS interface assumptions; reproduce in CI and obtain independent review |

Every complete scoped proof must still choose a logic/kernel, machine model
and interface to physical execution. An assumed OS operation in a model is
not a proof that a deployed filesystem implements that operation.

## All-pairs journal goals

The journal gate now verifies ten M28 lemmas. The two previously open all-pairs
statements are included with their exact conclusions and no added premise:

- `committed_pins_never_decrease`: for every two `JournalCleared(slot, tx, g,
  r)` events in the same slot, an earlier event has `r1 << r2`.
- `a_generation_commits_at_most_once`: two `JournalDurable` events in the same
  slot with the same generation occur at the same time.

Both formulas mention only emitted rule actions. The witness
`two_successive_commits_advance` exhibits two successive real commits with
concrete generations
`successor('initial')` and `successor(successor('initial'))`, two cleanups and
a strict revision advance, so neither goal is vacuous. The existing
crash/recovery witness remains reachable.

The [local proof evidence](proof-logs/current/journal-all-pairs/README.md)
retains complete proof trees and records the rejected, vacuous predecessor.
Hosted reproduction of this journal increment passed on [5fa4e9f](https://github.com/lucannez64/VELA/actions/runs/40065136343).

The proofs use a linear `Chain(slot, generation, pin)` ghost fact added to
`Initialize`, `PersistJournal` and `ClearJournal`. It follows the durable
phase, advancing when the journal becomes pending and remaining unchanged
through cleanup. No guard or security restriction was added.

The [F★ encoding proof](../formal/m28-trace-equivalence/README.md) checks
step/trace lifting, projection and Chain well-formedness for typed,
initialized, single-slot machines. It is not an equivalence proof of the
`.spthy` sources: original Tamarin traces must still embed into the core
encoding, and their lifts must still yield admissible instrumented Tamarin
traces. Input derivability, global freshness, term representation and slot
projection remain source-bridge obligations. The generic F★ transfer theorem
requires the encoded safety property as a proof argument; it does not prove
the two all-pairs goals or import their Tamarin verdicts. The actual verdicts
are therefore for the instrumented model. The handwritten proof adds no Rust
postconditions. [Local evidence](proof-logs/current/journal-encoding-equivalence/README.md)
records a fresh check with caching disabled, pinned tool version, argv and
module hash; hosted reproduction of this new step is pending.

The journal runner first runs `check-action-atoms.py` on M28 and M29. It strips
comments and string literals, collects each rule's action name/arity, and
rejects lemma or restriction atoms whose fact is not an emitted action. The
regression fixture `tests/vacuous-action-atom.spthy` is rejected for
`DiskClean/5`; the real models pass. This catches the historical vacuity shape
but does not certify soundness. Tests cover both explicit trace qualifiers
(`all-traces` and `exists-trace`), wrong arities, comments, and malformed input.
The default journal proof timeout is 600 seconds per model; the memory cap
and single-worker setting are unchanged.

A matching hash, finite tests, unproved annotation, ideal primitive, new axiom
or mocked database cannot substitute for these obligations. No unsupported
computational reduction, full Rust/Kotlin/Swift refinement or whole-system
completion claim is supplied here. The Tamarin↔F★ source bridge and real
Rust/filesystem refinement of M28 remain open.

# M28 typed single-slot encoding equivalence and encoded all-pairs goals

`M28TraceEquivalence.fst` proves equivalence of two handwritten, typed,
initialized, single-slot transition encodings, one with Chain and one without,
and proves the two all-pairs goals on the encoded event traces. **It does not
machine-check the connection to `.spthy`, prove a Tamarin theorem, or close
Rust/filesystem refinement.** It supplies a checked kernel within the larger,
still-partial correspondence argument.

## Checked statements

| Declaration | Statement within the F* encodings |
|---|---|
| `step_core_to_lift` | Each core step lifts with identical base state and event |
| `step_lift_projects` | Each lifted step projects with identical base state and event |
| `reach_core_lifts` | Each initialized core trace lifts with the same encoded events |
| `reach_lift_projects` | Each initialized lifted trace projects with the same events |
| `reach_lift_wf` | Reachable Chain equals `chain_of_phase` |
| `lift_chain_premise_clean`, `lift_chain_premise_applied` | The well-formed phase supplies the matching Chain pair |
| `transfer_lifted_to_original`, `transfer_original_to_lifted` | Transfer schemas for an **input proof** of a predicate over the corresponding encoded reachable traces |
| `journal_generation_at_most_once` | Named formula: two `EJournal` occurrences with the same generation have the same timepoint |
| `reach_core_journal_unique`, `reach_lift_journal_unique` | The quantified body of the generation formula, proved for every reachable core trace and transferred to `reach_lift`; the revision order is arbitrary and unused |
| `clear_pins_strictly_increase` | Named formula: for every ordered pair of `EClear` occurrences, the strict-order record relates the earlier pin to the later pin |
| `reach_core_clear_pins_strict`, `reach_lift_clear_pins_strict` | The quantified body of the pin formula, proved for every reachable core trace and transferred to `reach_lift` |
| `term_order` | Concrete unary free-term proper-subterm strict order, with checked transitivity and irreflexivity |
| `two_commits_reach`, `two_commits_reach_lift` | Checked two-commit witness in the core encoding and in the lifted encoding |
| `two_commits_clear_goal`, `two_commits_journal_goal`, `two_commits_lift_clear_goal`, `two_commits_lift_journal_goal` | The exact quantified bodies of the two named formulae, specialized to the witness trace |
| `two_commits_ordered` | Concrete occurrence indices, generations, generation depths and strict pin increase on the witness |

The step correspondence is parametric in `lt`, with no order laws required.
The pin theorem is parametric in an explicit `strict_order` record with
transitivity and irreflexivity proofs; no law is assumed of an arbitrary `lt`.
The generation proof counts journal events and is independent of `lt`. `hp` in
the transfer schema is an argument, not a discharged security theorem.

## Concrete order and the two-commit witness

The concrete revision algebra in this module has the constant `TInit` and the
unary constructor `TSucc`; `subterm` is proper subterm and `term_order` bundles
it with checked `subterm_trans` and `subterm_irrefl` proofs. There are no
axioms, admitted goals or solver-option escapes in this instance.

The checked witness is a single reachable trace (`two_commits_reach`) with two
complete journal/vault/clear cycles:

| Timepoint | Event | Generation / pin |
|---|---|---|
| 0 | `EInitialized` | `G0` / `TInit` |
| 1 | `ESnapshotRead` | `G0` / `TInit` |
| 2 | `EJournal` | `GS G0`; pin `TInit` to `TSucc TInit` |
| 3 | `EVault` | `GS G0` / `TSucc TInit` |
| 4 | `EClear` | `GS G0` / `TSucc TInit` |
| 5 | `ESnapshotRead` | `GS G0` / `TSucc TInit` |
| 6 | `EJournal` | `GS (GS G0)`; pin `TSucc TInit` to `TSucc (TSucc TInit)` |
| 7 | `EVault` | `GS (GS G0)` / `TSucc (TSucc TInit)` |
| 8 | `EClear` | `GS (GS G0)` / `TSucc (TSucc TInit)` |

`two_commits_reach_lift` is the same trace in the lifted encoding, obtained
through the checked `reach_core_lifts` map. `two_commits_ordered` records the
indices (journals 2 and 6, clears 4 and 8), the generations `GS G0` and
`GS (GS G0)` with depths 1 and 2, and the strict pin increase from
`TSucc TInit` to `TSucc (TSucc TInit)`. The witness is an inhabited encoded
trace, not merely initialization, and it instantiates the all-pairs theorems
on the core and lifted encodings. It is F* non-vacuity for this encoding; it
is **not** a Tamarin witness and does not establish source reachability.

`two_commits_clear_goal` and `two_commits_journal_goal` (and the
`two_commits_lift_clear_goal` / `two_commits_lift_journal_goal` versions) are
wrappers whose statements are exactly the quantified bodies of
`clear_pins_strictly_increase` and `journal_generation_at_most_once` at the
witness trace. They call the checked parametric theorems rather than assuming
them.

## Scope of the concrete order

`term_order` is a concrete instance of the encoded revision parameter only.
It is **not** the full Tamarin subterm algebra/order, not a source embedding,
and not evidence that arbitrary Tamarin terms or global freshness are
represented by these unary terms. The pin goal remains available for other
revision types through the parametric `strict_order` record. No property of
the concrete order is used to strengthen the equivalence theorems.

## Reviewed rule/fact mapping

| Tamarin rule | Core / lifted encoding | Encoded event |
|---|---|---|
| Initialize | `init_core` / `init_lifted`, reachability initial case | `EInitialized` |
| ReadSnapshot | `CReadSnapshot` / `LReadSnapshot` | `ESnapshotRead` |
| PersistJournal | `CPersistJournal` / `LPersistJournal` | `EJournal` |
| PersistVault | `CPersistVault` / `LPersistVault` | `EVault` |
| ClearJournal | `CClearJournal` / `LClearJournal` | `EClear` |
| Crash | `CCrash` / `LCrash` | `ECrash` |
| OpenVault | `COpenVault` / `LOpenVault` | `EOpened` |

`EJournal` carries the old/new revisions of the source's simultaneous
`RevisionIncreases` and `JournalDurable` actions. Snoc order corresponds to
within-slot event order; no source action-predicate translation is proved.
`Clean`, `Pending` and `Applied` represent the durable product facts;
`opened` represents Profile; `ready` represents membership in ReadyGeneration;
`snaps` plus `split` represents linear Snapshot consumption. Ready is an
append-only list with duplicates; only membership is read. Chain is the extra
lifted pair. This table is a reviewed transcription, not a source parser proof.

## Open source embeddings

To transfer a Tamarin verdict to the original source requires both directed
obligations, not merely equivalence of these two encodings:

1. Original Tamarin traces projected to the relevant slot embed into
   `reach_core` with matching event order/fields.
2. Lifting the image of each such trace produces a trace admissible in the
   actual instrumented Tamarin system.

Both are unproved. Specific differences that must be handled:

- A fixed initialized slot omits global interleavings and empty/uninitialized
  profile traces. Those are benign for the intended implication-shaped goals
  only after a projection argument; not for arbitrary trace predicates.
- The local state does **not** represent all global `Fr` facts. `used`
  enforces transaction non-reuse within one slot and does not model global
  `Fr(~tx)` freshness against other slots or other message values. The earlier
  claim that all global `Fr` were represented in local state, and the older
  header's advocacy of a global projection, are withdrawn.
- `rev`, `tx` and `msg` are opaque type parameters, and generation is a separate
  datatype. No erasure/embedding from Tamarin's single term domain is proved.
- Attacker input derivability and output knowledge are omitted. Arbitrary
  revision/payload arguments over-approximate `In`: for example the encoded
  initial item can be supplied as a payload even though the source's fresh
  initial item was never sent to the attacker.
- `lt` must be instantiated with the intended strict-subterm relation, and the
  intended action predicates/all-pairs formulae must be related to the events.
  The checked concrete `term_order` covers only the unary encoded instance
  above; it is not the full Tamarin `<<` algebra or a source embedding.

These are scope obligations, not local axioms added to make a theorem pass.
No Tamarin restriction was weakened. The fixed initialized single-slot types
are not `.spthy` semantics. Checking a stronger-looking F* theorem does not by
itself imply the actual Tamarin theorem. A direct Tamarin proof on the seven
original rules did not finish within 600 seconds. The ten M28 / eleven M29
verdicts remain separate; their counts are not increased by this module, and
the Tamarin models, rules and guards are unchanged by this proof work.

## Reproduction and trust

Run `vela-heavy security/formal/m28-trace-equivalence/verify.sh` with pinned
F* 2025.10.06 (or `VELA_FSTAR_BIN` pointing to it). The journal gate calls that
same command. Verification disables checked-module caching, pins bundled Z3
4.13.3, and logs version, module hash and arguments. The source guard rejects
local proof escapes/options and requires the expected equivalence, all-pairs,
concrete-order and witness definitions; its tests are drift checks, not
theorem or semantic-adequacy proofs. A fresh run's log, module hash, tool
version and counts are retained under
`evidence/journal-encoded-goals/`.

The formal CI job installs the checksum-pinned prebuilt F* release independently
of the existing hax cache. Local heavy commands remain serialized under 3 GiB,
no swap and one worker. F*'s logic, standard library, solver and toolchain remain
trusted. This handwritten model proof is separate from the Rust extraction
inventory: it adds **zero Rust postconditions** (the count remains 245) and
makes no Rust, filesystem or whole-system refinement claim.

# M28 typed single-slot encoding equivalence

`M28TraceEquivalence.fst` proves equivalence of two handwritten, typed,
initialized, single-slot transition encodings, one with Chain and one without.
**It does not machine-check the connection to `.spthy`, prove either all-pairs
security goal, or close Rust/filesystem refinement.** It supplies a checked
kernel within the larger, still-partial correspondence argument.

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

The step correspondence is parametric in `lt`, with no order laws required.
That is sufficient for equivalence, not for a pin-monotonicity theorem.
`hp` in the transfer schema is an argument, not a discharged security theorem.
No definitions of the two all-pairs goals occur here; the Tamarin proofs are
separate results on different trace domains.

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
- `used` enforces transaction non-reuse within one slot. It does not model
  global `Fr(~tx)` freshness against other slots or other message values.
- `rev`, `tx` and `msg` are opaque type parameters, and generation is a separate
  datatype. No erasure/embedding from Tamarin's single term domain is proved.
- Attacker input derivability and output knowledge are omitted. Arbitrary
  revision/payload arguments over-approximate `In`: for example the encoded
  initial item can be supplied as a payload even though the source's fresh
  initial item was never sent to the attacker.
- `lt` must be instantiated with the intended strict-subterm relation, and the
  intended action predicates/all-pairs formulae must be related to the events.

These are scope obligations, not local axioms added to make a theorem pass.
No Tamarin restriction was weakened. A direct Tamarin proof on the seven
original rules did not finish within 600 seconds. The ten M28 / eleven M29
verdicts remain separate; their counts are not increased by this module.

## Reproduction and trust

Run `vela-heavy security/formal/m28-trace-equivalence/verify.sh` with pinned
F* 2025.10.06 (or `VELA_FSTAR_BIN` pointing to it). The journal gate calls that
same command. Verification disables checked-module caching, pins bundled Z3
4.13.3, and logs version, module hash and arguments. The source guard rejects
local proof escapes/options and requires the expected definitions; its tests
are drift checks, not theorem or semantic-adequacy proofs.

The formal CI job installs the checksum-pinned prebuilt F* release independently
of the existing hax cache. Local heavy commands remain serialized under 3 GiB,
no swap and one worker. F*'s logic, standard library, solver and toolchain remain
trusted. This handwritten model proof is separate from the Rust extraction
inventory: it adds **zero Rust postconditions**.

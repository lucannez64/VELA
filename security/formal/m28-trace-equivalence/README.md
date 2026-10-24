# Machine-checked M28 Chain correspondence

`M28TraceEquivalence.fst` is a checked F* development of the transition
systems on both sides of the M28 `Chain` instrumentation.  It replaces the
manual projection/lifting paragraph that previously connected the original
seven-rule model (`b8221e7`) to the instrumented model used by the Tamarin
gate.

The F* module is verified with `fstar.exe` (see `verify.sh`).  It contains no
`assume`, `admit`, axiom, or external oracle.  The only inputs are the two
rule encodings described below.

## What is proved

The module is polymorphic in the strict-increase guard `lt`; it never
interprets `lt`, so the result is independent of the concrete order on
revisions.

| F* declaration | Statement |
|---|---|
| `step_core_to_lift` | Every original rule instance has a lifted rule instance with the same event and the same non-Chain state. |
| `step_lift_projects` | Every lifted rule instance projects to an original rule instance with the same event and the same non-Chain state. |
| `reach_core_lifts` | Every reachable original event trace has a reachable lifted event trace with exactly the same event list. |
| `reach_lift_projects` | Every reachable lifted event trace projects to a reachable original event trace with exactly the same event list. |
| `reach_lift_wf` | In every reachable lifted state, `Chain` equals `chain_of_phase` of the durable phase. |
| `lift_chain_premise_clean`, `lift_chain_premise_applied` | On a well-formed state, the `Chain = (gen,pin)` premise of the instrumented rules follows from the durable-phase equation. |
| `transfer_lifted_to_original` | Any predicate on event traces proved for all reachable lifted traces holds for all reachable original traces. |
| `transfer_original_to_lifted` | The converse transfer also holds. |

The two all-pairs journal goals are predicates on the emitted action events
(and their timepoint order).  Because the event list, including its order, is
identical on both sides, `transfer_lifted_to_original` is the machine-checked
step that moves the Tamarin verdicts from the instrumented model to the
original model.

## Rule mapping

One slot is fixed.  This is sound because every M28 rule mentions exactly one
slot, no rule relates two slots, and all per-slot facts are independent; a
global trace restricted to one slot is a trace of the encoded machine.  The
two all-pairs goals are per-slot.

| Tamarin M28 rule | Original F* constructor | Lifted F* constructor | Event / actions |
|---|---|---|---|
| `Initialize` | initial `init_core` | initial `init_lifted` | `EInitialized` / `Initialized` |
| `ReadSnapshot` | `CReadSnapshot` | `LReadSnapshot` | `ESnapshotRead` / `SnapshotRead` |
| `PersistJournal` | `CPersistJournal` | `LPersistJournal` | `EJournal` / `RevisionIncreases` and `JournalDurable` |
| `PersistVault` | `CPersistVault` | `LPersistVault` | `EVault` / `VaultDurable` |
| `ClearJournal` | `CClearJournal` | `LClearJournal` | `EClear` / `JournalCleared` |
| `Crash` | `CCrash` | `LCrash` | `ECrash` / `Crash` |
| `OpenVault` | `COpenVault` | `LOpenVault` | `EOpened` / `Opened` |

`Snoc h e` is chronological append, so list order is Tamarin's `<` on
timepoints.  A `PersistJournal` event is one timepoint that emits both
`RevisionIncreases` and `JournalDurable`; the event carries the same
`old`/`next` fields.

## State-fact mapping

| Tamarin fact | F* representation |
|---|---|
| `DiskClean(slot,g,p,rev,payload)` | `Clean g p rev payload` |
| `DiskPending(slot,tx,g,next,payload,vrev,vpayload)` | `Pending tx g next payload vrev vpayload` |
| `DiskApplied(slot,tx,g,p,intended,vrev,vpayload)` | `Applied tx g p intended vrev vpayload` |
| `!Profile(slot)` | `opened = true` |
| `!ReadyGeneration(slot,g,p)` | `(g,p)` is in `ready` |
| `Snapshot(slot,tx,g,p)` | `(tx,g,p)` is in `snaps`; `split` consumes one occurrence, matching linearity |
| fresh `Fr(~tx)` in `ReadSnapshot` | `tx` is not in `used`; it is then added to `used` |
| `Chain(slot,g,p)` | the `chain` field of `lifted` |

`In`, `Out` and payload values are arbitrary inputs or non-security outputs;
they do not guard any event used by the two goals and are omitted from the
event vocabulary.  Revisions, payloads, item values, and transaction identifiers
are type parameters (`rev`, `msg`, `tx`) treated opaquely.

The `Increasing` restriction is the parameter `lt`.  `PersistJournal` requires
`lt old next = true`.  The F* theorems quantify over every `lt`, so the proof
covers any interpretation of strict increase, including strict subterm.

## Sorts

Transaction identifiers, revisions and payloads are distinct type parameters
(`tx`, `rev`, `msg`).  Tamarin uses one term sort.  No M28 rule guard compares
a value from one of these positions with a value from another: snapshots are
matched position by position, `RevisionIncreases` compares two revisions, and
payloads are carried opaquely.  Consequently the typed encoding neither adds
nor removes a transition: a Tamarin trace maps to a typed trace by erasing the
sort distinction, and a typed trace maps back by choosing distinct
representatives for the finitely many values in each sort.  The two all-pairs
goals compare only revisions/generations and event order, so this mapping is
exact for them.  The mapping remains a reviewed argument, not a parser-level
translation of the `.spthy` file.

## Fidelity and residual gaps

* The F* rule encodings above are a reviewed manual transcription of the
  `.spthy` rules.  There is no parser- or semantics-level refinement from the
  Tamarin source into F*; the table is the complete mapping used.
* The Tamarin gate still proves the two all-pairs lemmas in the instrumented
  model.  A direct Tamarin proof on the seven original rules was attempted and
  did not finish inside the 600 s bound; the checked F* equivalence is the
  allowed alternative.  The manual "delete Chain" argument is no longer used.
* No claim is made about the Rust/filesystem implementation, the OS, the
  compiler, or primitive security.  The concrete M28-to-code refinement remains
  open.

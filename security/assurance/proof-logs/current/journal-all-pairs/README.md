# M28 all-pairs journal increment (local evidence)

This directory records a parent working-tree reproduction of the corrected
M28 model from delegated commit `f920627` (integrated as `1983ca7`). The parent
also corrected trace-qualifier parsing in the source guard, added six Python
regressions, and raised only the journal wall-clock limit to 600 seconds per
model. The shared local limit remains 3 GiB, no swap, one proof worker.
Hosted reproduction of this increment passed on `5fa4e9f`
([workflow](https://github.com/lucannez64/VELA/actions/runs/40065136343));
that run predates the later typed F★ encoding proof. These are local results, not an external audit.

Command from the repository root:

```bash
PATH="$HOME/.local/opt/vela-tools/bin:$PATH" \
VELA_PROOF_OUT=/tmp/vela-m28-parent-review \
"$HOME/.local/opt/vela-tools/bin/vela-heavy" \
security/formal/run-share-journal-proofs.sh
```

Pinned versions: Tamarin 1.12.0 and Maude 3.5.1. The complete model outputs
include version headers and proof trees. `runner.log` contains the source
guard/regression results and final M28/M29 verdict counts. The checked model
hash is recorded in the reviewed correspondence file and assurance manifest.

The two new universal statements use only emitted actions:

- Any two ordered `JournalCleared` events in the same slot have strictly
  increasing pins.
- Two `JournalDurable` events with the same slot and generation have the same
  event time.

A new exists-trace witness performs two successive commits and cleanups with
strict pin increase. The existing crash/recovery witness remains checked.
The full gate checks all ten M28 and eleven M29 results, including the seven
original M28 statements; selective proving is not the evidence used here.

The model adds linear Chain ghost state. The lifting/projection argument in
[the correspondence note](../../../../formal/share-journal-correspondence.md)
remains manual at the Tamarin source boundary. A later
[typed F★ encoding proof](../journal-encoding-equivalence/README.md) checks
lifting/projection inside the encodings; it does not establish the source
embeddings or concrete Rust/filesystem execution. Full-system formalization and implementation refinement remain open.

## Rejected predecessor

Delegated commit `6d38227` was never integrated. Its added formulas referred
to state facts (`DiskClean`, `DiskApplied`, `Snapshot`) as trace events, although
no rule emits those actions. Those antecedents are unreachable, so the reported
15 successful results did not prove the intended properties. The old assertion
that trace formulas observe state-fact creation times was incorrect.
`rejected-guard.log` records rejection of all seven affected formulas by the
new source guard. The guard checks emitted names/arities; it cannot establish
reachability, model adequacy, or proof soundness. The explicit two-commit
witness supplies additional reachability evidence for this model.

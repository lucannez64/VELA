# Client share journal step

Pure, dependency-free state machine for the desktop share journal. The real
journal code in `desktopVELA/vela-desktop-core/src/sharing.rs` reads
`shares.enc` and `vault.enc`; this crate owns only the durable phase between
those writes and returns the filesystem effects the shell must perform.

```
Clean --PersistJournal--> Pending --ApplyToVault--> Applied --Clear--> Clean
           ^                  |                                 |
           |                  +--ReArm (same-content rewrite)---+
           |                                                    |
           +--------------- Recover (re-arm, apply, clear) <----+
```

## Types

| Type | Meaning |
|---|---|
| `JournalState { generation, phase, pending, pins }` | The durable journal facts. `phase` is `Clean`, `Pending` or `Applied`; `Applied` is in-memory only (a pending record on disk decodes as `Pending`). |
| `JournalImage { generation, pending, pins }` | Exactly what a `shares.enc` replacement publishes. |
| `PendingItem { id, had_before }` | Shell-side pending item identity; the shell keeps the `VaultItem` payloads. |
| `SharePin { slot, revision }` | One pinned received share. The M28 slot projection is P3b work. |
| `JournalEvent` | `ReadSnapshot`, `PersistJournal`, `ReArm`, `ApplyToVault`, `Clear`, `Crash`, `Recover`. |
| `JournalEffect` | `WriteJournal(image)`, `WriteVault`, `ClearJournal(image)`. |
| `JournalStep { state, effects }` | The next state and the effects, in order. |

`step` is total: invalid events are no-op steps with an empty effect list and
unchanged state. There is no I/O, clock, randomness, serialization or crypto in
this crate.

## Guarantees checked by the gate

`verify-fstar-journal.sh` extracts the crate with hax and checks it with F*:

* `step` is total (no precondition, no `Option` result).
* `step.state.generation >= state.generation` for every state and event.
* `clear_step` preserves the generation (P1 finding 1).
* `plan_commit` emits journal, re-arm, vault, clear in that order, and the
  clear image keeps the generation the journal image published.

See `security/assurance/proof-logs/current/journal-step-extraction/README.md`
for the mapping to `security/formal/m28_share_journal.spthy` and the exact
commands and results.

## Reproduction

```bash
cargo test --manifest-path libVELA/vela-client-share-journal/Cargo.toml
security/assurance/bounded.sh libVELA/vela-client-share-journal/verify-fstar-journal.sh
```

The gate fails if a proof tool is missing, extraction fails, an escape or
unreviewed option appears, or F* rejects a postcondition.

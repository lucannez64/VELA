# P3a — Share journal step extraction

Scope: extract the durable share-journal transition relation of
`desktopVELA/vela-desktop-core/src/sharing.rs` into a pure, dependency-free
crate, make the desktop code execute only the effects that step returns, and
check the step's first obligations with hax/F*. This is the input to P3b
(journal step refines Tamarin M28); it does not claim the refinement itself.

Base commit: `ba4785e`. The line numbers below are from the finished worktree.

Sources read for this increment:

- `security/assurance/proof-logs/current/journal-inventory/README.md` (P1)
- `security/formal/m28_share_journal.spthy`
- `security/formal/share-journal-correspondence.md`
- `desktopVELA/vela-desktop-core/src/sharing.rs` (journal path) and
  `store.rs` (`save_vault`/`load_vault`/`write_secret_file`)
- `libVELA/vela-client-share-policy/src/lib.rs` and its `verify-fstar.sh`
- `.github/workflows/security.yml` refinement matrix and
  `security/formal/tests/test_proof_inputs.py`

---

## 1. What was added

New crate `libVELA/vela-client-share-journal` (no dependencies; only `Vec` and
scalar types, plus `hax-lib` under `cfg(hax)`):

| Item | Location | Role |
|---|---|---|
| `JournalPhase` | `src/lib.rs:38` | `Clean`, `Pending`, `Applied`; `Applied` is in-memory only. |
| `PendingItem { id, had_before }` | `:51` | Journal-side identity of one pending vault change; the shell keeps the `VaultItem` payloads. |
| `SharePin { slot, revision }` | `:59` | Pins carried in the state; the M28 one-slot projection is P3b work. |
| `JournalImage` | `:66` | Exactly what a `shares.enc` replacement publishes. |
| `JournalState` | `:74` | `generation`, `phase`, `pending`, `pins`. |
| `JournalEffect` | `:83` | `WriteJournal(image)`, `WriteVault`, `ClearJournal(image)`. |
| `JournalEvent` | `:94` | `ReadSnapshot`, `PersistJournal`, `ReArm`, `ApplyToVault`, `Clear`, `Crash`, `Recover`. |
| `JournalStep` | `:126` | `{ state, effects }`; effects are in execution order. |
| `step` | `:235` | Total transition relation; invalid events are no-op steps. |
| `commit_is_authorized` / `next_generation` | `:215` / `:203` | The generation guard shared by `step` and the commit plan. |
| `CommitEffects` / `plan_commit` | `:134` / `:397` | Canonical item-commit reference: journal, re-arm, vault, clear. |
| `plan_recovery` / `clear_step` | `:455` / `:488` | Canonical recovery sequence and the generation-preserving clear wrapper. |

No I/O, clock, randomness, serialization or AEAD lives in the crate. The shell
converts its encrypted `ShareStore` into `JournalState` at the call site.

## 2. Event and effect semantics

| Event | Valid in | Effect(s) | State change |
|---|---|---|---|
| `ReadSnapshot` | any | none | Adopts the disk image; a pending record becomes `Pending`. An older generation is ignored so a read cannot rewind. |
| `PersistJournal` | `Clean`, no pending, generation = snapshot, `< u64::MAX` | `WriteJournal(image)` | generation + 1; `Pending` when items exist, otherwise `Clean` (metadata-only save). |
| `ReArm` | `Pending` | `WriteJournal(same image)` | none (idempotent stutter). |
| `ApplyToVault` | `Pending` | `WriteVault` | `Applied`. |
| `Clear` | pending exists | `ClearJournal(same generation, no pending)` | `Clean`. |
| `Crash` | any | none | none (durable files unchanged). |
| `Recover` | any | none in `Clean`; otherwise `WriteJournal`, `WriteVault`, `ClearJournal` | `Clean`, same generation. |

A commit's canonical effects are therefore journal → re-arm → vault → clear;
the re-arm is the extra journal write P1 finding 1 records (O1), and clear
keeps the generation.

## 3. Mapping to M28 (using P1's table)

| M28 rule | This step | Desktop call site |
|---|---|---|
| `ReadSnapshot` | `JournalEvent::ReadSnapshot` (state construction) | `read_share_store` → `journal_state` (`sharing.rs:179`) |
| `PersistJournal` | `PersistJournal` event | `save_share_store` (`sharing.rs:372`) |
| `PersistVault` | `ApplyToVault` / the `WriteVault` effect of `Recover` | `perform_journal_effects` (`sharing.rs:269`) |
| `ClearJournal` | `Clear` / the `ClearJournal` effect of `Recover` | same |
| `Crash` | `Crash` event (tests only; process death is outside the shell) | — |
| recovery composite (`Crash` then apply/clear/open) | `Recover` event | `finish_pending_items` (`sharing.rs:315`) called from `load_share_store` / `recover_share_commit` |
| re-arm stutter (no M28 rule) | `ReArm` inside `Recover` | `finish_pending_items` before the vault write |
| metadata-only generation advance (no M28 rule) | `PersistJournal` with an empty pending list | `save_share_store` (D in P1 §3.3) |

The M28 state facts carried here are the generation and the pin list; pending
items are the payload identity. `Chain` is proof instrumentation in M28 and is
not modelled. `vrev`/`vpayload` provenance labels are not serialized (P1 §4.2).

## 4. Desktop rewiring

- `journal_state`, `journal_pending` and `journal_pins` (`sharing.rs:179–216`)
  project the real `ShareStore` into the pure model.
- `perform_journal_effects` (`sharing.rs:269`) is the only interpreter: it
  performs each returned effect in order, updates the in-memory snapshot only
  when the corresponding write succeeds, and keeps the existing
  `share-write`/`vault` test checkpoints.
- `save_share_store` (`sharing.rs:372`) keeps the already-proved
  `next_store_generation` refusal, calls `step(PersistJournal)`, asserts the two
  decisions agree, then performs the returned effects.
- `finish_pending_items` (`sharing.rs:315`) calls `plan_recovery` and performs
  its three effects; a failed re-arm still stops before the vault write.
- On-disk format and generation numbering are unchanged: the shell writes its
  existing `ShareStore` at the image's generation and clears `pending_items` on
  the clear effect.

New tests (in `sharing.rs`) check the shell performs exactly the step's plan:

| Test | What it asserts |
|---|---|
| `commit_performs_exactly_the_step_effects` (`:1606`) | Observed effects equal `plan_commit(...).effects.into_effects()`; clear keeps the journal generation and leaves no pending items. |
| `metadata_only_commit_performs_only_the_journal_write` (`:1638`) | Empty-pending save performs exactly the one `WriteJournal` the step returned. |
| `recovery_performs_exactly_the_step_effects` (`:1661`) | After an interrupted journal checkpoint, recovery performs exactly `plan_recovery(...).effects`. |

The test hook records the image reconstructed from the real store, not the
effect value, so a wrong generation/pending/pin write would fail the comparison.

## 5. Gate and results

`libVELA/vela-client-share-journal/verify-fstar-journal.sh`:

1. runs `cargo test` for the crate;
2. regenerates `proofs/fstar/extraction` with `cargo hax into` (selected entry
   points only) and checks it plus the hand-written lemma module with
   `security/formal/check-driver-proof-sources.py`;
3. runs `fstar.exe` without `--lax` on the extracted module and
   `proofs/fstar/journal-lemmas/Vela_client_share_journal_lemmas.fst`.

The F* postconditions/lemmas prove:

| Obligation | Where |
|---|---|
| `step` is total | extracted function has no precondition and a `JournalStep` result; `step_is_total` in the lemma module |
| generation never decreases | `step_result_is_sound` + `generation_never_decreases` |
| clear keeps the generation | `clear_step` ensures + `clear_keeps_generation` |
| commit effects are journal, re-arm, vault, clear in order | `plan_commit` ensures `commit_effects_match_spec` + `commit_effects_are_journal_vault_clear` |
| recovery effects are journal, vault, clear in order | `plan_recovery` ensures `recovery_plan_matches_spec` + `recovery_effects_are_journal_vault_clear` |

Commands and results (run through `vela-heavy`, `VELA_STEP_TIMEOUT=3600`,
`CARGO_TARGET_DIR` under the worktree):

```text
libVELA/vela-client-share-journal/verify-fstar-journal.sh
  cargo test: 8 passed
  Driver source policy: 1 extracted modules, 1 proof modules; no unreviewed escapes/options
  Verified module: Vela_client_share_journal
  Verified module: Vela_client_share_journal_lemmas
  All verification conditions discharged successfully

desktopVELA: cargo test -p vela-desktop-core --lib
  463 passed; 0 failed; 8 ignored

python3 -I security/formal/check-no-proof-escapes.py
  169 F* files: no proof escapes, no unimplemented interfaces.

python3 -I security/formal/tests/test_proof_inputs.py
  3 tests OK
```

The gate's final line reports these content hashes:

```text
f20309aecf538fcad62e7295243b901d58b384cd80b1e66d99bb94cee51b9a4e  proofs/fstar/extraction/Vela_client_share_journal.fst
f20bdcf0a9af2591c0ccc6b737547397101f803d8a0c8a059c9dfa54caf0b2f1  proofs/fstar/journal-lemmas/Vela_client_share_journal_lemmas.fst
1b4c17835fb184cf947d54e9db3c5eb348746ac868e0e2fd8ef6c398d8c55dae  src/lib.rs
```

The committed extraction is regenerated by the gate (the matrix entry sets
`fresh: true`, `ships: true`). The matrix entry is
`share-journal` in `.github/workflows/security.yml:361`.

## 6. What P3b still needs

1. **Slot projection.** `SharePin.slot` is the received-share vector index; M28
   has one slot. P3b must fix one lineage as the slot and frame the others.
2. **Pin ordering.** Step carries pins but does not yet prove
   `committed_pins_never_decrease` or `pins_advance_on_every_commit`; the
   current `commit_effects_match_spec` compares pin *counts*, not contents.
3. **Batch semantics.** One `PersistVault` can apply a vector of pending items
   (P1 finding 3); P4 owns the collection equality and first-wins duplicate
   semantics.
4. **Generation quotient.** Metadata-only saves advance the generation without
   an M28 payload (P1 finding 2); P3b must relate them to stutter or add a
   metadata rule.
5. **May-step for uncertain writes.** `write_secret_file` can fail after
   rename (P1 finding 5), so one Rust write maps to {stutter | modelled step}.
   The `Crash` event is a test-level abstraction, not an implementation.
6. **Transaction identity.** M28's fresh `~tx` is derived from the generation
   at which the pending record was written; the proof must state that mapping.
7. **Local edits/deletions and recovery outside the RMS lock** remain P5/P6,
   as P1 records.

## 7. Unverified

- No Tamarin run was made for this step; the M28 verdicts cited are from
  `security/formal/m28_share_journal.spthy` and P1.
- The mapping in §3 is manual. The F* gate checks the pure step's obligations,
  not that the shell's `write_secret_file`/`save_vault` calls have the
  durability the model assumes (that is P3c/P3d).
- Pin-content equality and the exact set of `shares.enc` writers outside
  `vela-desktop-core` are not re-audited here.
- A full `cargo test` of the desktop workspace and the gpui/Tauri apps was not
  run; only the required `cargo test -p vela-desktop-core --lib` was.

# M23 sync-admission assurance record

The client sync engine is the last high-value pure decision surface: it
decides whether a server response may enter the local vault. A malicious or
buggy server that could roll an item back to an earlier Lamport clock, skip
the device past a rotation transition, or adopt a capsule bound to a
different epoch would silently corrupt vault history. M23 verifies every
accept/refuse decision on that boundary.

## Layers

| Layer | Tool | What is proven |
|---|---|---|
| `libVELA/vela-sync-policy` | hax → F* (11 entry points) | The decision logic itself: epoch-adoption ladder, chunk-download admission, merge classification |
| `security/formal/m23_sync_admission.spthy` | Tamarin (8 lemmas) | Protocol-level consequences against an adversarial server |
| `desktopVELA/vela-desktop-core/src/sync.rs` | cargo test (389) | Handlers consume verified permits; no decision computed inline |

## Decisions extracted to F*

- `plan_epoch_adoption(EpochAdoptionFacts)` — the adopt/keep/refuse ladder:
  refuse freezing rotations, refuse rollback (`server < local`), refuse
  skipped transitions (`server ≠ local+1`, carried as the relational
  observation `server_epoch_is_next`), require the capsule's inner epoch and
  rotation id to bind to this exact transition. Negative theorems:
  rollback, skip, freezing, and foreign-capsule facts can never authorize.
- `plan_chunk_download(ChunkDownloadFacts)` — a chunk is admitted only when
  its clock is at least the recorded one, it decrypted under epoch-bound
  AAD, and the key epoch is positive. Witness theorem: a device holding
  Lamport 7 refuses a server revision at 3.
- `classify_merge_action(ItemMergeFacts)` — tombstones always win;
  conflicted local edits are never overwritten by newer server copies;
  unsynced-local-edit-vs-newer-server surfaces as a user-resolved conflict.
  Exhaustively tested over all 16 boolean combinations.

One arithmetic atom — `server_epoch == local_epoch + 1` — crosses as the
caller-supplied observation `server_epoch_is_next`: hax 0.3.7's F* prelude
leaves i64 arithmetic unencoded (while-loop internals), so the transition
relation crosses as a fact while every other conjunct and the full decision
structure stay inside the verified boundary.

## Tamarin results

```text
every_admitted_chunk_was_served                    verified
recorded_clock_fact_comes_from_admission           verified
clock_recorded_event_comes_from_admission          verified
adoption_requires_successor_of_local               verified
adopted_epoch_differs_from_retired                 verified
every_adoption_has_an_advertised_epoch             verified
adopted_epoch_was_never_retired_before             verified
adoption_is_reachable                              verified
```

Epoch succession is encoded with a public `succ` constructor so "exactly
local + 1" is structural pattern-matching: rollback (predecessor), skips
(`succ ∘ succ`), and unrelated epochs cannot match the adoption premise.

## Verification output

Historic pre-revision run (8 lemmas) is superseded. Captured output for the
current fuel-bounded revision:

```text
m23_sync_admission: 11 verified
every_admitted_chunk_was_served / recorded_clock_fact_comes_from_admission /
clock_recorded_event_comes_from_admission /
recorded_clocks_are_trusted_bootstrap_values /
admitted_clocks_are_validated_against_the_trusted_record /
adoption_requires_successor_of_local / adopted_epoch_differs_from_retired /
every_adoption_has_an_advertised_epoch /
adopted_epoch_was_never_retired_before /
trusted_first_sync_is_reachable / adoption_is_reachable
— all 11 verified, 0 falsified, 0 warnings (0.3 s)
```

The gate derives the expected count from the theory itself.

Toolchain: tamarin-prover 1.12.0, Maude 3.5.1, UTF-8 locale.

Reproduce with:

```sh
./security/formal/run-sync-admission-proofs.sh
cd libVELA/vela-sync-policy && ./verify-fstar.sh
```

## Post-review revision (2026-08-26/27)

`RecordOnFirstSync` no longer admits an unrecorded clock: first-sync admission
requires the device's trusted bootstrap clock. Re-verified for THIS exact
revision (fuel-bounded model, see header): **all 11 lemmas verified** locally
under a hard memory cap and in CI (tamarin-prover 1.12.0).

Scope restrictions — do not over-claim:
- The clock surface admits only the BOOTSTRAP clock value, recorded once.
  Later clocks ADVANCING from admitted server-supplied revisions (the real
  client's monotonic succ-based admission) are NOT modeled; the two
  "trusted bootstrap value" lemmas hold only for this bootstrap-only
  surface. Advancing-revision admission is future work.
- The epoch ladder is bounded to TWO adoptions per device via AdoptionFuel;
  "never retired before"-style lemmas hold within that bound.

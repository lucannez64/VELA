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

```text
m23_sync_admission: 8 verified
m23 sync-admission formal proof gate: 8 verified, 0 falsified, 0 warnings
```

Toolchain: tamarin-prover 1.12.0, Maude 3.5.1, UTF-8 locale.

Reproduce with:

```sh
./security/formal/run-sync-admission-proofs.sh
cd libVELA/vela-sync-policy && ./verify-fstar.sh
```

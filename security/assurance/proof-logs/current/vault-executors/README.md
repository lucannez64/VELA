# Vault, rotation and device-capsule executors against a store model (F-1)

## Claim

The vault upload, vault mutation and rekey drivers assume their executors
report the truth about what their SQL and sled operations did. For eight
executors that assumption is now proved against a store model, for every
starting state and failing statement, and checked on the real stores (turso
and sled). Verified on 9e29b40. The eight executors are:

- `GetChunkIo`, `PutChunkIo` and `DeleteChunkIo` (`vault/chunk.rs`);
- `PutOramIo` (`vault/oram.rs`);
- `RekeyIo` (`vault/rekey.rs`);
- `ActivateIo` (`vault/schema.rs`);
- `CapsuleAckIo` (`device/capsule.rs`);
- `CapableIo` (`device/list.rs`).

Each method is a thin loop (plan → render → run → classify) over pure pieces
in `vela-rekey-policy/src/executor.rs`. hax extracts the plans and
classifiers. All SQL and store text moved there verbatim and is pinned byte
for byte by unit tests. `vela-server/src/vault/sql.rs` runs the loop.

## Model

`Vela_rekey_policy_executor_model.fst` has 26 statement kinds (`VaultStmt`):

- chunk reads, create, shadow upsert, version compare-and-swap update and
  delete, and the epoch sweeps;
- the freeze, commit and rollback compare-and-swaps on the account row;
- shadow activity, capsule writes, clears and acknowledgements;
- the capable attestation;
- ORAM bucket reads, inserts and compare-and-swap updates;
- the schema floor;
- the completeness probes, inventory and `Commit`.

Its semantics:

- a guarded insert checks its guard before the uniqueness constraint;
- guarded updates and deletes report exact row counts;
- `run_auto` runs each statement on its own;
- `run_tx` publishes only at `Commit`;
- `cas_tx` runs the rest of the plan only if the compare-and-swap changed the
  row;
- a failure can be injected at any statement, including the commit.

## Exact theorems

`Vela_rekey_policy_executor_lemmas.fst`, for every starting state and fault
point:

- **24 honesty theorems:**
  - chunks: `delete_chunk_is_honest`, `read_version_is_honest`,
    `reread_is_honest`, `lookup_chunk_is_honest`, `chunk_create_is_honest`,
    `chunk_shadow_is_honest`, `chunk_update_is_honest` and
    `inventory_is_honest`;
  - devices, ORAM and schema: `probe_is_honest`, `ack_capsule_is_honest`,
    `pending_is_honest`, `attest_capable_is_honest`,
    `schema_floor_is_honest`, `oram_write_is_honest`,
    `write_capsule_is_honest` and `shadow_activity_is_honest`;
  - rotation: `freeze_cas_is_honest`, `freeze_transaction_is_honest`,
    `freeze_guard_is_honest`, `commit_cas_is_honest`,
    `commit_sweep_is_honest`, `commit_guard_is_honest`,
    `rollback_cas_is_honest` and `rollback_publishes_is_honest`.
- **Facts the drivers rely on:**
  - `chunk_create_needs_active_account` and
    `chunk_delete_needs_active_account`;
  - `shadow_write_runs_only_inside_the_attempt`;
  - `ack_clears_only_its_epoch`;
  - `commit_publishes_complete_chunks` and
    `commit_publishes_complete_devices`;
  - `rollback_discards_attempt_output`;
  - `freeze_requires_a_clean_account`.

Every module is checked in its own process under 630 MB, `--z3rlimit 100`, no
admits: `Executor` 31 s, `executor_model` 32 s, `executor_lemmas` 64 s.

## Mutations

`verify-fstar-vault-executors-mutations.sh`; each mutant must fail the named
theorem:

| Mutant | Rejected at |
|---|---|
| `classify-error`: a zero-row delete reports `Deleted` | `delete_chunk_is_honest` |
| `classify-rows`: a zero-row compare-and-swap reports `Updated` | `chunk_update_is_honest` |
| `classify-ack`: a zero-row acknowledgement reports `Cleared` | `ack_capsule_is_honest` |
| `plan-swap`: the capsule goes to the caller's device, not the target | `write_capsule_is_honest` |
| `plan-drop`: the transaction commit is dropped | `freeze_transaction_is_honest` |
| `guard-drop`: the model's chunk delete ignores the account-epoch guard | `delete_chunk_is_honest` |

## Real-store conformance

`vela-server/src/vault/conformance.rs` runs the real executors on turso and
sled. A failure is injected at every query, execute, commit and store write.
Each case compares every touched table and the schema key with the Rust
mirror.

| Family | Cases | With a failure |
|---|---|---|
| Chunks | 1,728 | 936 |
| Rotation | 696 | 492 |
| Devices, ORAM and schema | 540 | 306 |
| **Total** | **2,964** | **1,734** |

The schema check pins the modelled columns of `vault_chunks`, `users`,
`devices` and `oram_buckets`, and shows a duplicate chunk key is rejected.

## Findings

- No pre-existing executor was found dishonest.
- The delegate's first rollback classifier expected three outcomes, but the
  abort transaction has four statements (compare-and-swap, chunk delete,
  capsule clear, commit). It would have reported a successful rollback as a
  storage error. This was caught while proving and fixed before commit; a
  regression test pins the four-statement form.

## Assumptions and limits

- **Inputs, not proved:** the five completeness probes, the inventory row set
  and the two `NOT EXISTS` answers of the account compare-and-swaps are
  `EXISTS` or multi-row queries the table model cannot decide. They are model
  inputs. The theorems prove only that the executors report them honestly;
  conformance checks them against turso.
- Each statement is atomic and requests serialize.
- **Not covered yet:**
  - route resolution (`load_key_state`, `maybe_rollback`,
    `resolve_write_epoch`, `read_epoch`);
  - the quota reads;
  - `shadow_authority`;
  - transaction begin;
  - the recheck and publish reads;
  - path validation;
  - `get_capsule`;
  - `list_devices`.

## Reproduction

```bash
cd serverVELA/vela-rekey-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh     # chains verify-fstar-vault-executors.sh
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server --lib vault::conformance
```

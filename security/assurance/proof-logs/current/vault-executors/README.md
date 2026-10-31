# Vault, rotation and device-capsule executors against a store model (F-1)

## Claim

The vault upload, vault mutation and rekey drivers assume their executors
report the truth about what their SQL and sled operations did. For eight
executors that assumption is proved against a store model, for every starting
state and failing statement, and checked on the real stores (turso and sled).
Wave 2 extends the same model and lemmas to the handler I/O that ran outside
any executor method (below). Verified on the wave-2 commit. The eight
executors are:

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

### Wave 2: the I/O outside the executor methods

The same plan → render → run → classify shape now covers, with the same
`VaultStmt` enum, model and lemma module:

- `rekey::load_key_state`'s `users` read — the row behind `load_state`,
  `maybe_rollback`, `resolve_write_epoch`, `read_epoch`, `shadow_authority`,
  and through them `chunk.rs::recheck_state` and `oram.rs::recheck_bucket`;
- the transaction begin of `RekeyIo::begin_freeze_transaction`,
  `rollback_rekey` and `get_capsule`;
- `vault::current_usage_bytes`' two `SUM(LENGTH(ciphertext))` reads;
- `vault::enforce_rekey_shadow_quota`'s projected-storage read;
- `oram::get_path`'s per-bucket read;
- `sync::get_sync`'s chunk-manifest read;
- `schema::minimum`'s sled read of `vault-schema:{user}`;
- `get_capsule`'s devices-join-users read and its read-once clear;
- `list_devices`'s `LIMIT 1000` device listing.

`publish`/`publish_path`/`publish_epoch` are an in-process broadcast
(`vault/events.rs`), not database or store state, so they need no plan.

## Model

`Vela_rekey_policy_executor_model.fst` has 41 statement kinds (`VaultStmt`) —
the 30 wave-1 kinds plus the wave-2 `SelectKeyState`, `SelectUsageChunks`,
`SelectUsageOram`, `SelectRekeyProjection`, `SelectOramRow`,
`SelectSyncManifest`, `SchemaFloorGet`, `BeginTransaction`, `SelectCapsule`,
`ClearEnrollmentCapsule` and `SelectDeviceList`:

- chunk reads, create, shadow upsert, version compare-and-swap update and
  delete, and the epoch sweeps;
- the freeze, commit and rollback compare-and-swaps on the account row;
- shadow activity, capsule writes, clears and acknowledgements;
- the capable attestation;
- ORAM bucket reads, inserts and compare-and-swap updates;
- the schema floor write and read;
- the completeness probes, inventory and `Commit`;
- the wave-2 reads: the account's rotation row, the two usage sums, the
  projected usage, an ORAM path bucket, the sync manifest, a pending capsule,
  the device listing, and the transaction begin.

Its semantics:

- a guarded insert checks its guard before the uniqueness constraint;
- guarded updates and deletes report exact row counts;
- `run_auto` runs each statement on its own;
- `run_tx` publishes only at `Commit`;
- `run_begin` is one statement that changes nothing;
- `cas_tx` runs the rest of the plan only if the compare-and-swap changed the
  row;
- a failure can be injected at any statement, including the commit and the
  begin.

The wave-2 sums are the model's own: `LENGTH(ciphertext)` is
`FStar.String.length` over the stored base64 text (ASCII, so bytes are
characters), summed over the finite chunk and ORAM tables at the account's
served epoch, which the read accepts only when the query returned exactly it.
The manifest and listing reads likewise accept only the row set computed from
the state, so no returned row is a free input.

## Exact theorems

`Vela_rekey_policy_executor_lemmas.fst`, for every starting state and fault
point:

- **24 wave-1 honesty theorems:**
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
- **9 wave-2 honesty theorems:**
  - `key_state_is_honest`: `Loaded` is exactly the account's seven rotation
    cells, `NotFound` a missing account, `Storage` a failed read;
  - `usage_is_honest` and its corollary `usage_measured_is_stored`: the two
    usage reads report the account's current-epoch ciphertext bytes;
  - `projection_is_honest`: the projected-storage read reports the state's
    projected bytes after replacing the one chunk;
  - `oram_read_is_honest`: the served path bucket is the stored row at the
    caller's account, tree, index and epoch;
  - `sync_is_honest`: `Read` only for exactly the account's rows at the served
    epoch;
  - `schema_floor_read_is_honest`: `Stored` is exactly the key's value;
  - `capsule_read_is_honest`: the capsule, its epoch and the recorded rotation
    id (only when the epochs match) are the stored row's;
  - `capsule_clear_is_honest`: only the caller's own device row is cleared,
    and only when the statement ran;
  - `device_list_is_honest`: `Read` only for exactly the account's device rows;
  - `begin_transaction_is_honest` and `begin_plan_is_one_statement`: the
    begin is one statement, `Committed` exactly when it ran, and it changes
    nothing.
- **Facts the drivers rely on:**
  - `chunk_create_needs_active_account` and
    `chunk_delete_needs_active_account`;
  - `shadow_write_runs_only_inside_the_attempt`;
  - `ack_clears_only_its_epoch`;
  - `commit_publishes_complete_chunks` and
    `commit_publishes_complete_devices`;
  - `rollback_discards_attempt_output`;
  - `freeze_requires_a_clean_account`;
  - `loaded_key_state_is_stored`.

Every module is checked in its own process under 710 MB, `--z3rlimit 100`, no
admits: `Executor` 56 s, `executor_model` 28 s, `executor_lemmas` 64 s.

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
| `freeze-oram`: the freeze guard drops the ORAM check | `freeze_requires_a_clean_account` |
| `commit-shadows`: the commit guard drops the shadow check | `commit_publishes_complete_chunks` |
| `commit-devices`: the commit guard drops the device check | `commit_publishes_complete_devices` |
| `key-state-failed`: a failed key-state read reports `NotFound` | `key_state_is_honest` |
| `key-state-missing`: a missing account reports `Storage` | `key_state_is_honest` |
| `usage-error`: a failed usage read reports `Measured 0` | `usage_is_honest` |
| `usage-swap`: the chunk total reads the ORAM table | `usage_is_honest` |
| `projection-error`: a failed projected read reports `Measured 0` | `projection_is_honest` |
| `oram-error`: a failed bucket read reports `Missing` | `oram_read_is_honest` |
| `oram-plan`: the bucket read asks the next epoch | `oram_read_is_honest` |
| `sync-error`: a failed manifest read reports `Read` | `sync_is_honest` |
| `sync-plan`: the manifest read asks the next epoch | `sync_is_honest` |
| `schema-error`: a failed store read reports `Stored None` | `schema_floor_read_is_honest` |
| `schema-plan`: the store read asks an empty key | `schema_floor_read_is_honest` |
| `capsule-error`: a failed capsule read reports `Missing` | `capsule_read_is_honest` |
| `capsule-clear-error`: a failed clear reports `Cleared` | `capsule_clear_is_honest` |
| `devices-error`: a failed listing reports `Read` | `device_list_is_honest` |
| `devices-plan`: the listing asks an empty account | `device_list_is_honest` |
| `begin-drop`: the begin plan drops its statement | `begin_plan_is_one_statement` |
| `begin-fault`: the model's begin ignores the injected failure | `begin_transaction_is_honest` |

## Real-store conformance

`vela-server/src/vault/conformance.rs` runs the real executors and handler I/O
on turso and sled. A failure is injected at every query, execute, commit,
begin and store read/write. Each case compares every touched table and store
key with the Rust mirror, and for the manifest and listing it also compares
the exact row set (`model::sync_row_set`, `model::device_list_row_set`).

| Family | Cases | With a failure |
|---|---|---|
| Chunks | 1,728 | 936 |
| Rotation | 696 | 492 |
| Devices, ORAM and schema | 540 | 306 |
| Handler I/O (wave 2) | 375 | 192 |
| **Total** | **3,339** | **1,926** |

The schema check pins the modelled columns of `vault_chunks`, `users`,
`devices` and `oram_buckets`, and shows a duplicate chunk key is rejected.

## Findings

- No pre-existing executor was found dishonest.
- The delegate's first rollback classifier expected three outcomes, but the
  abort transaction has four statements (compare-and-swap, chunk delete,
  capsule clear, commit). It would have reported a successful rollback as a
  storage error. This was caught while proving and fixed before commit; a
  regression test pins the four-statement form.
- Wave 2 found no dishonest handler read. Two behaviour traps were preserved
  deliberately: the capsule query's rotation id compares two SQL cells, where
  a `NULL` on either side is not a match (the model writes it as a `match` on
  both options, not `== None`), and `schema::minimum` treats a non-UTF-8
  stored value as invalid, which the read's lossy text view keeps.

## Assumptions and limits

- **Inputs, not proved:** the five completeness probes, the inventory row set
  and the two `NOT EXISTS` answers of the account compare-and-swaps are
  `EXISTS` or multi-row queries the table model cannot decide. They are model
  inputs. The theorems prove only that the executors report them honestly;
  conformance checks them against turso.
- Each statement is atomic and requests serialize.
- `LENGTH(ciphertext)` is the model's character count of the stored base64
  text; the engine's own `LENGTH` and the mirror's `.len()` are checked by
  conformance, not proved equal.
- The schema key holds UTF-8 text (`"2"`); a non-UTF-8 value is read as
  replacement text and therefore invalid, as before.
- The listing's engine order (`ORDER BY created_at ASC`) is not modelled: the
  model's row set is the table's own order, and conformance uses states whose
  `created_at` order equals the table order.
- The floor interpretation (absent → 1, `"2"` → 2, else invalid) and the
  key-state normalization (epoch floor, `freezing` test) are two-line handler
  policy over the proved read observation, pinned by unit tests.
- **Still outside a plan:** the per-account re-key pacing limiter
  (`rate_limit::check`, `rl:rekey:{user}`) — a shared fixed-window sled
  counter with a TTL, outside the scope list for this part of wave 2. Its
  window is abstracted as a scheduler choice. Path index arithmetic
  (`oram::path_bucket_indices`) and header parsing are pure, not I/O.

## Reproduction

```bash
cd serverVELA/vela-rekey-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh     # chains verify-fstar-vault-executors.sh
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server --lib vault::conformance
```

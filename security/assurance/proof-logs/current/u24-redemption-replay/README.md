# U-24: a lost recovery-redemption reply is recovered from the device row

`POST /recovery/enroll-device` consumed the recovery grant, inserted the
recovered-device row and only then wrote the response. A client whose
connection dropped never learned `device_id`, and the retry presented a
consumed grant, so the preflight answered `401 "recovery grant expired or
already used"` while the device row existed. This is the recovery counterpart
of U-20 (pairing result), which was closed the same way: the committed row
records the grant, and the lost reply is reconstructed from it under the same
authorization check.

## The fix

* `devices.recovery_grant_id TEXT` (fresh schema, tolerant `ALTER` on upgrade,
  `CREATE UNIQUE INDEX idx_devices_recovery_grant_id`). It is written by the
  guarded recovered-device `INSERT` in the same statement that writes the row,
  so the row and its grant commit together. Schema homes:
  `serverVELA/vela-server/src/db.rs` (`init_schema`,
  `migrate_rekey_schema`) and `serverVELA/vela-server/src/sqldb.rs`
  (`ALTERS`, `CREATE TABLE devices`, index batch). The export/import tool
  (`src/migration.rs`) copies the turso file verbatim and the server re-runs
  the same `ALTER`s on open, so it needs no column list.
* `POST /recovery/enroll-device` builds its `RedemptionStart` from the checked
  preflight: `Redeem(ready)` when a live grant was observed, `Replay` when the
  preflight's own rejection is `GrantUnavailable` (the policy only produces
  that reason for an absent grant). Every other rejection keeps its historical
  status and message before the driver runs.
* The `Replay` ceremony has exactly one effect,
  `plan_enrolled_device`: `SELECT id, hybrid_ek, hybrid_vk FROM devices WHERE
  user_id = ? AND recovery_grant_id = ?`. `classify_replay` reports
  `Enrolled { key_matches }` with exact text equality of the stored keys and
  the request's re-encoded `hybrid_ek`/`hybrid_vk`, or `Absent`. Only
  `Enrolled { key_matches: true }` produces `Complete` (the `200` with that
  row's `device_id`); `Enrolled { key_matches: false }` and `Absent` produce
  the same `Fail(GrantUnavailable)` the missing-grant path always rendered.
  A query or decode failure has no observation and aborts with the retained
  error, exactly like the other read effects.
* The driver never enters `Consume`, `Insert`, `Recheck` or `RestoreAndFail`
  from `Replay`, so a replay cannot enroll a second device or re-arm a
  consumed grant. The unique index is a second wall: if a second guarded
  insert ever carried a used grant, the statement errors and the driver treats
  the error as terminal (no restoration), as it already did for ambiguous
  insert errors (U-19).

## Proofs

Driver (`vela-recovery-policy`, `proofs/fstar/driver-lemmas` and
`proofs/fstar/driver-composition`):

* `trace_sound`/`redemption_state_is_sound` gained the replay clauses and are
  still proved equal by stage case analysis (`trace_sound_matches_rust`), now
  over six stages. A replay state has no consumption, permit, insert attempt,
  insert success or restoration fact, and a replay success is terminal.
* `redemption_effect_is_sound` requires `Replay` to be emitted only from the
  `Replay` stage, and `Complete` to come either from an insert success (the
  redemption) or from `replay_succeeded` (the replay), never both.
* `redemption_trace_theorem` is stated for a `RedemptionStart`, so the
  per-request theorem covers both starts: the final state is sound, a success
  is never paired with a restoration, and there is at most one `Complete`.
* `replay_never_inserts`: for an arbitrary event list, the replay start's
  trace contains zero `Insert` effects.
* `replay_complete_only_from_a_matching_row`: a `Complete` effect can only
  answer `Replayed (Enrolled { key_matches = true })`.
* `replay_refusal_is_grant_unavailable`: an absent row and a different-key row
  are both `Fail(GrantUnavailable)`.
* `replay_success_is_reachable`, `replay_mismatch_is_reachable`,
  `replay_absent_is_reachable`: non-vacuity witnesses from the extracted
  begin.
* Composition: new `SpawnReplay`/`ReplayDone` actions. `one_grant_at_most_one_device`
  is unchanged and still holds for every schedule that mixes redemption,
  rotation, expiry and replay requests; `spawn_replay_keeps_rows` /
  `replay_done_keeps_rows` show the replay steps never change the row counter;
  `replay_writes_no_second_device` and `v2_ok` are the matching-key and
  different-key witnesses over the shared world.

Interpreter (`proofs/fstar/redemption-interpreter-lemmas`): `responds_to`,
`turn_ev`, `remaining` and `step_decreases` gained the `Replay` effect, so
`run_redemption` is proved to call the executor's `replay_enrolled_device`
exactly once for the emitted `Replay` effect and to end in
`run_from_start start evs`. `run_redemption_theorem` is stated for both
starts. The cancellation evidence is in
[../cancellation/README.md](../cancellation/README.md) (H3): the generic
`redemption_cancellation` covers every start, and
`redemption_replay_cancellation` restates it at the extracted loop with
`RedemptionStart_Replay`; the interpreter gate below checks both. Their
sha256 (`55649004...` for the lemma module, `2eddecad...` for
`src/redemption_interpreter.rs`) is printed by that gate.

Store model (`proofs/fstar/redemption-lemmas`, F-1):

* `db` models the unique index as `grant_index`; the guarded insert writes the
  row with `dv_grant = Some grant` and sets `grant_index grant = Some id`, and
  a second insert for a used grant is refused (`insert_with_used_grant_is_refused`).
* `replay_finds_the_inserted_device`: for every starting database, guard and
  fault point, if the insert reported `Inserted` then the replay lookup
  returns exactly `{ device_id; hybrid_ek; hybrid_vk }` — the device the first
  request created.
* `replay_rejects_a_different_key`: different key material yields
  `Enrolled { key_matches = false }`.
* `replay_without_a_row_is_absent`: no indexed row yields `Absent`.
* `vector_replay_enrolled` is the concrete shared vector, mirrored by
  `redemption_model.rs::tests::shared_vectors`.

## Tests

* `serverVELA/vela-server/src/recovery/conformance.rs`,
  `replay_lookup_matches_the_store_model`: real turso + sled against the Rust
  mirror for five device-table shapes (no row, this grant/user, another grant,
  another user, no grant) and every fault point; a match returns the row's id,
  a mismatch/absence returns `Absent`, a fault aborts with an error.
* `guarded_insert_matches_the_store_model` now also checks that the inserted
  row records the grant, that the replay finds the same device id, and that a
  second insert for the same grant is refused.
* `serverVELA/vela-server/tests/integration.rs`,
  `enroll_device_recovers_the_device_after_a_lost_reply`: the first `200` is
  discarded (a dropped connection), the retry returns the same `device_id`,
  a different key returns the historical `401` message, and the account keeps
  exactly one recovered device row. Verified to fail without the fix: with the
  replay arm temporarily replaced by the historical rejection, the test fails
  with `left: 401, right: 200` at the retry assertion.
* `enroll_device_redeems_grant_exactly_once` was updated: a racing loser can
  now either lose the atomic take (`401`) or arrive after the row committed
  and replay it (`200`); the test asserts both successful answers name the one
  recovered device and exactly one recovered row exists.
* `serverVELA/vela-server/tests/recovery_possession_model.rs` model gained the
  U-24 replay arm (a consumed grant whose device row committed answers `200`
  for the same keys), and still passes all bounded traces.
* New load-bearing mutants in `verify-fstar-recovery-executors-mutations.sh`:
  `classify-replay` (any row reports `key_matches = true`) is rejected at
  `replay_rejects_a_different_key`; `plan-grant` (the insert records the user
  as the grant) is rejected at `insert_device_is_honest`.

## Commands and results

All run through `~/.local/opt/vela-tools/bin/vela-heavy` from
`serverVELA/vela-recovery-policy` with `VELA_STEP_TIMEOUT=3600` and a private
`CARGO_TARGET_DIR`.

| Command | Result |
|---|---|
| `./verify-fstar-driver.sh` | pass; "driver proof: 6 focused Rust contracts, 23 hand-written trace lemmas/witnesses checked"; "driver composition: any number of interleaved requests write at most one device row per grant" |
| `./verify-fstar-redemption-interpreter.sh` | pass; loop/executor/turn/verdict/cancellation lemmas checked |
| `./verify-fstar-recovery-executors.sh` | pass; executor honesty incl. `replay_finds_the_inserted_device`; 36/36 mutants rejected |
| `cargo test -p vela-recovery-policy` | pass; 0 failed: lib 43, `fact_construction` 8, `possession_driver` 17, `redemption_driver` 16, `webauthn_driver` 23, doc 0 |
| `cargo test -p vela-server` | pass; 0 failed: lib 125, main 0, `account_deletion_model` 1, `challenge_single_use_model` 3, `device_revocation_model` 7, `enrollment_ceremony_model` 3, `integration` 72, `login_driver_handler` 5, `pairing_model` 5, `recovery_lifecycle_model` 6, `recovery_possession_model` 1, `rekey_state_model` 5, `session_capability_model` 3, `share_channel_model` 2, doc 0 (cargo reports the lib binary twice; both runs pass) |

## Assumptions and limits

* SQL/store linearizability, statement atomicity and the unique index
  semantics are assumptions of the model, as in F-1; the conformance test
  checks the model against turso and sled, it does not prove the database.
* The replay lookup is not a fresh ceremony: it answers only the row whose
  stored keys equal the request's, and the answer is only the device id (no
  token, no key material). An attacker who already holds the grant cannot use
  it to enroll or to retrieve a device for another key.
* If the retry races the original request's insert (the lookup runs before
  the insert commits), the lookup is `Absent` and the retry gets the
  historical `401`; another retry after the commit succeeds. This is a
  liveness race, not a safety gap, and is not claimed by the theorems.
* A device row migrated from the legacy stoolap backend does not carry the new
  column (the legacy bootstrap column list is unchanged, as U-20 left it), so a
  pre-migration device cannot be recovered by this path; it can still be
  recovered from a fresh redemption.
* The grant index is not consulted when a live grant is present; a live grant
  can only coexist with a row for it if a redemption completed and the grant
  was re-armed, which the driver never does. If that invariant were broken,
  the guarded insert would fail (unique index) and report `500`, never a
  second device.

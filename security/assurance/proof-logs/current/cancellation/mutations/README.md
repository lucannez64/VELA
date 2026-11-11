# Cancellation mutation checks

One mutation per policy crate. Each turns a driver transition into the
"success before the effect finished" mistake: a flag that the state predicate
only allows after the corresponding effect is set on the preceding observation.
The copied pristine extraction and the diff are under
`/tmp/vela-f2-cancel-mut/<crate>/`; the diffs and failure logs are in this
directory.

The extracted driver is passed explicitly to F* together with the interpreter
extraction and its cancellation lemma. (A plain include directory can serve a
stale `.checked` module, so passing the mutated file explicitly is what makes
the check real; the normal gate gets the same freshness from `cargo hax`.)

| Crate | Mutation | Obligation that fails |
|---|---|---|
| vela-session-policy | `on_devices_scanned` sets `f_committed = true` before the transaction | `step`'s soundness postcondition (error 19, `Deletion_driver.fst`) |
| vela-enrollment-policy | `on_ceremony_taken` sets `f_inserted = true` before the insert | `step`'s soundness postcondition (error 19, `Pairing_driver.fst`) |
| vela-recovery-policy | `on_consumed` sets `f_insert_succeeded = true` before the insert | `step`'s soundness postcondition (error 19, `Driver.fst`) |
| vela-rekey-policy | `on_write` sets `f_activity_done = true` on a non-shadow write | `step`'s soundness postcondition (error 19, `Vault_upload_driver.fst`) |
| vela-share-policy | `on_rows` (update) sets `f_revoked = true` on an update | `step`'s soundness postcondition (error 19, `Driver.fst`) |

Each failure is the step-level soundness obligation the cancellation lemma
consumes: `sound_transition` is exactly `*_state_is_sound` plus
`*_effect_is_sound`, so a prefix that can reach the mutated state cannot be
proved sound. The unmutated gates pass (see the crate verify logs).

The same early-flag mutation cannot be made to pass by weakening the proof
predicate: the state predicates are independently restated in the extracted
driver and in the proof lemmas, and the interpreter lemma keeps the extracted
one.

## Second wave (commit 4329328)

The loops added after the first wave got their cancellation lemmas later, with
one more mutation per crate of the same kind. Each fails with error 19 on the
mutated driver's step postcondition; the originals pass in each crate's full
gate.

| Crate | Mutation | Obligation that fails |
|---|---|---|
| vela-rekey-policy | `chunk_on_version` sets `f_deleted = true` before the delete | `chunk_delete_step` postcondition (`Vault_mutation_driver.fst`): [diff](chunk-version-sets-deleted.diff), [log](chunk-version-sets-deleted.log) |
| vela-enrollment-policy | `on_account_checked` sets `f_inserted = true` before the insert | step postcondition (`Enroll_driver.fst`): [diff](enroll-account-sets-inserted.diff), [log](enroll-account-sets-inserted.log) |
| vela-session-policy | `on_device_insert` sets `f_committed = true` before the commit | step postcondition (`Registration_driver.fst`): [diff](registration-insert-sets-committed.diff), [log](registration-insert-sets-committed.log) |
| vela-recovery-policy | the not-staged branch sets `f_update_applied = true` | step postcondition (`Recovery_share_driver.fst`): [diff](recovery-share-sets-update-applied.diff), [log](recovery-share-sets-update-applied.log) |
| vela-share-policy | `on_view_consumed` sets `f_delivered = true` before delivery | step postcondition (`Send_driver.fst`): [diff](send-view-sets-delivered.diff), [log](send-view-sets-delivered.log) |

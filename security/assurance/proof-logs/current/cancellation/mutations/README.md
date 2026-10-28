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

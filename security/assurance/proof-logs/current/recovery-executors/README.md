# Recovery executor honesty against a store model (F-1)

## Claim

The recovery drivers assume their executor objects report the truth about what
their key-value and SQL operations did. That assumption is proved against a
store model, for every starting state and every failing operation, and checked
against the real stores (turso and sled), for:

- **device redemption:** `EnrollDeviceIo`
  (`serverVELA/vela-server/src/recovery/enroll_device.rs`);
- **recovery share:** `PutShareIo`, `FinalizeShareIo`, `GetShareIo` and
  `DeleteShareIo` (`serverVELA/vela-server/src/recovery/mod.rs`);
- **possession proof:** `InitiateProofIo` and `RecoverProofIo`
  (`serverVELA/vela-server/src/recovery/possess.rs`);
- **WebAuthn recovery:** `InitiateIo`
  (`serverVELA/vela-server/src/recovery/initiate.rs`), `RecoverIo`
  (`vela-server/src/recovery/recover.rs`), and `RegisterStartIo` /
  `RegisterFinishIo` (`vela-server/src/recovery/webauthn.rs`).

Every recovery executor family is now covered, and so is the I/O that was
still outside an executor (wave 2, F-1):

- the non-consuming `observe_enroll_grant` preflight peek;
- `post_enroll_device`'s preflight account `SELECT`;
- the startup `backfill_webauthn_cred_ids` scan and its per-row writes;
- every recovery rate-limit counter (`recovery_initiate_by_ip`,
  `recovery_initiate_by_ip_user`, `recovery_initiate_by_user`,
  `recovery_recover_by_ip_user`, `recovery_recover_by_user`,
  `recovery_enroll_by_ip`, `recovery_enroll_by_ip_user`,
  `recovery_enroll_by_user`, `webauthn_register_by_user`).

WebAuthn ceremony results (challenges, registration states, assertion results,
updated credential metadata) stay inputs.

## Design

Every executor method is a thin loop (plan → render → run → classify) over pure
pieces. The redemption pieces live in
`vela-recovery-policy/src/redemption_store.rs`; the recovery-share pieces live
in `vela-recovery-policy/src/share_store.rs`; the possession pieces live in
`vela-recovery-policy/src/possession_store.rs`; the WebAuthn pieces live in
`vela-recovery-policy/src/webauthn_store.rs`.

Redemption statements:

- `TakeGrant { key }`: an atomic get-and-delete of
  `recovery:enroll_grant:{user}:{grant}`.
- `PeekGrant { key }`: the non-consuming read of the same key
  (`observe_enroll_grant`).
- `SelectEnrollmentAccount { user }`: `post_enroll_device`'s preflight read of
  `key_epoch`, `rekey_state`, `recovery_webauthn_cred_id` and
  `recovery_auth_hash`.
- `InsertDevice { .., epoch, guard }`: `INSERT … SELECT … WHERE EXISTS` over
  the user's id, key epoch and rekey state, plus a guard:
  - `Credential { credential_id }` for a WebAuthn grant;
  - `Commitment` for a possession grant.
- `SelectAuthority { user }`: reads the recovery credential id and
  authentication hash.
- `PutGrant { key, value, grant }`: restores the grant with a 600 s TTL.

Recovery-share statements:

- `StageShare { .. }`: the guarded update that stages a candidate share, split
  id, epoch and possession commitment only while the account is at the request
  epoch, outside rotation, with no active share or split.
- `PromoteStagedSplit { .. }`: the guarded update that publishes the exact
  staged epoch/split and clears the candidate.
- `DeleteShare { .. }`: the guarded update that clears the active share, its
  split, the candidate and both commitments together.
- `SelectStageAccount` / `SelectFinalizeAccount` / `SelectShare`: the live-row
  reads used after a zero-row update and by `GET /recovery/share`.

Possession statements:

- `SelectInitiateAccount { user }`: the initiation row read
  (`recovery_share`, `recovery_auth_hash`, `key_epoch`, `rekey_state`).
- `ProofSlotExists { key }`: whether
  `recovery:possession:{user}:{attempt}` is occupied.
- `StoreProofChallenge { key, .. }`: the first-writer-wins `set_ex_nx` of the
  drawn challenge (300 s TTL).
- `TakeProofAttempt { key }`: the atomic read-and-delete of the exact attempt.
- `SelectProofAccount { user }`: the proof-recovery row read
  (`recovery_auth_hash`, `key_epoch`, `rekey_state`).
- `PutEnrollmentGrant { key, .. }`: the `set_ex` of the single-use grant
  (`recovery:enroll_grant:{user}:{grant}`, 600 s TTL).

WebAuthn statements:

- `SelectShare { user }` and `SelectCredential { user }`: the two availability
  reads (`recovery_share`, `recovery_webauthn_credential`) used by initiation,
  the authentication-finish context and registration start.
- `AuthSlotExists { key }`: whether
  `recovery:webauthn:auth:{user}:{attempt}` is occupied.
- `StoreAuthState { key, state, .. }`: the first-writer-wins `set_ex_nx` of the
  attempt envelope (300 s TTL).
- `TakeAuthState { key }`: the atomic read-and-delete of the exact attempt.
- `SelectFinishAccount { user }`: the live-row read
  (`recovery_share`, `key_epoch`, `rekey_state`, `recovery_webauthn_cred_id`,
  `recovery_split_id`).
- `UpdateCredentialIfCurrent { .. }`: the compare-and-swap credential write
  whose guard is the exact stored credential id.
- `SelectCredentialHolders { credential_id }`: the cross-account
  duplicate-credential lookup over `recovery_webauthn_cred_id`.
- `PersistCredential { .. }`: the registered credential write onto the caller's
  row.
- `StoreRegistrationState { key, .. }`: the overwriting `set_ex` of the
  registration ceremony state (`recovery:webauthn:register:{user}`, 300 s TTL).
- `TakeRegistrationState { key }`: the atomic read-and-delete of that state.
- `StoreCredentialGrant { key, grant, .. }`: the `set_ex` of the single-use
  credential-bound enrollment grant (600 s TTL).
- `SelectLegacyCredentials`: the startup backfill's scan of rows with a stored
  credential and no indexed id.
- `BackfillCredentialId { user, credential_id }`: the startup backfill's
  `UPDATE users SET recovery_webauthn_cred_id = ? WHERE id = ?`.

Rate-limit statements (`vela-recovery-policy/src/rate_store.rs`):

- `Incr { key, window_secs }`: one `Store::incr_fixed_window(key, 1, window)`
  at the endpoint's exact key and window, with an extracted admission
  classifier (`new count <= limit`).

`render` and the key constructors give the exact SQL, parameters, keys and
bytes used before, pinned byte for byte by unit tests.

## Exact theorems

`Vela_recovery_policy_redemption_lemmas.fst`,
`Vela_recovery_policy_share_lemmas.fst`,
`Vela_recovery_policy_possession_lemmas.fst`,
`Vela_recovery_policy_webauthn_lemmas.fst` and
`Vela_recovery_policy_rate_lemmas.fst`, for every starting state, row,
attempt slot, credential cell, credential index, registration slot, grant,
backfill candidate set, counter table and fault point:

- **Redemption operations:** `take_grant_is_honest`, `insert_device_is_honest`,
  `authority_observation_is_honest`, `restore_grant_is_honest`,
  `peek_grant_is_honest` and `enrollment_account_is_honest`.
- **Recovery-share operations:** `stage_share_is_honest`,
  `promote_staged_split_is_honest`, `delete_share_is_honest`,
  `stage_account_is_honest`, `finalize_account_is_honest` and
  `read_share_is_honest`. Each observation equals what the operation did to the
  modelled row; a failure changes nothing.
- **Possession operations:** `initiate_observation_is_honest`,
  `initiate_epoch_is_honest`, `store_challenge_is_honest`,
  `attempt_consumption_is_honest`, `proof_account_is_honest` and
  `grant_store_is_honest`. Every observation field is the live row's truth, the
  slot is fresh exactly when it was empty, a written challenge is exactly the
  drawn one, a lost `set_ex_nx` writes nothing, a consumed attempt is removed
  whether or not it decoded, and a stored grant is exactly the plan's grant at
  its key.
- **WebAuthn operations:** `auth_start_observation_is_honest`,
  `auth_start_store_is_honest`, `finish_context_is_honest`,
  `attempt_consumption_is_honest`, `credential_update_guard_is_honest`,
  `credential_update_is_honest`, `finish_account_is_honest`,
  `share_release_is_honest`, `grant_store_is_honest`,
  `registration_start_observation_is_honest`,
  `registration_state_store_is_honest`,
  `registration_state_consumption_is_honest`, `uniqueness_is_honest`,
  `credential_persist_is_honest`, `legacy_scan_is_honest`,
  `backfill_write_is_honest`, `backfill_run_is_honest`,
  `backfill_run_names_the_rows` and `backfill_only_touches_landed_rows`. Every availability, context, account,
  credential, split and uniqueness field is the live row's (or credential
  index's) truth; the attempt slot is fresh exactly when it was empty; a stored
  attempt is exactly the drawn envelope; a lost `set_ex_nx` writes nothing; a
  consumed attempt or registration state is removed whether or not it decoded;
  `Updated`/`Persisted` hold exactly when the guarded write changed a row, and
  then exactly the new credential cell and indexed credential id were written
  and the index seed moved with them; a zero-row update, a failed statement or a
  serialization failure changes nothing.
- **Rate limiters:** `rate_limit_is_honest`: the counter at the plan's key
  grows by exactly one (saturating), a failed store call changes no counter,
  and `Admitted` holds exactly while the new value is within the endpoint's
  limit.
- **Facts the drivers rely on:**
  - redemption: `take_match_is_the_stored_grant`, `take_is_single_use`,
    `inserted_device_is_owned_and_guarded`, `restored_grant_is_live`;
  - recovery share: `staged_candidate_is_exact`, `promoted_split_is_active`,
    `deleted_share_is_cleared`, `not_staged_keeps_state`;
  - possession: `fresh_observation_is_an_empty_slot`,
    `stored_challenge_is_the_drawn_one`, `lost_challenge_changed_nothing`,
    `consumed_attempt_is_single_use`, `corrupt_attempt_is_not_missing` and
    `issued_grant_is_live`;
  - rate limits: `rate_limit_only_counts_one` and
    `limited_only_past_the_limit`;
  - WebAuthn: `observed_credential_is_the_live_one`,
    `fresh_attempt_is_an_empty_slot`, `stored_attempt_is_the_drawn_one`,
    `lost_attempt_race_changed_nothing`, `consumed_attempt_is_single_use`,
    `consumed_attempt_bindings_are_the_removed_ones`,
    `corrupt_attempt_is_not_missing`, `updated_credential_is_the_new_one`,
    `released_share_is_the_rows_share`, `issued_credential_grant_is_live`,
    `registration_state_is_single_use`,
    `unique_credential_has_no_other_holder` and
    `persisted_credential_is_live`, `absent_peek_means_no_grant` and
    `account_facts_are_the_stored_row`.
- **Vectors:** 9 redemption `vector_*` lemmas (including `vector_peek_grant`
  and `vector_account`), 7 recovery-share `vector_share_*` lemmas, 12
  possession `vector_possession_*` lemmas, 29 WebAuthn `vector_webauthn_*`
  lemmas and 2 rate `vector_rate*` lemmas, shared with the Rust mirror
  (`redemption_model.rs`).

Each module is checked in its own process under 700 MB, `--z3rlimit 200`, no
admits. The recovery-share modules take 29–32 s at 589–622 MB peak; the redemption
modules take 27–32 s at 582–606 MB peak; the possession model and lemmas take
28–30 s at 596 MB / 579 MB peak; the WebAuthn store, model and lemma modules
take 30 s, 31 s and 35 s at 625 MB, 653 MB and 709 MB peak; the rate store,
model and lemmas take 27 s each at 569 MB, 558 MB and 568 MB peak.

## Mutations

`verify-fstar-recovery-executors-mutations.sh`; each mutant must fail the
named theorem:

| Mutant | Rejected at |
|---|---|
| `classify-match`: any taken grant matches | `take_grant_is_honest` |
| `classify-error`: a failed insert reports `Inserted` | `insert_device_is_honest` |
| `classify-rows`: a zero-row insert reports `Inserted` | `insert_device_is_honest` |
| `classify-authority`: a missing commitment reports `StillRotating` | `authority_observation_is_honest` |
| `plan-guard`: always uses the commitment guard | `insert_device_is_honest` |
| `plan-epoch`: a fixed epoch of 1 | `insert_device_is_honest` |
| `share-classify-stage-rows`: a zero-row stage reports `Staged` | `stage_share_is_honest` |
| `share-classify-account`: a non-matching share reports a match | `stage_account_is_honest` |
| `share-classify-read`: a missing share reports present | `read_share_is_honest` |
| `share-classify-delete-rows`: a zero-row delete reports `Deleted` | `delete_share_is_honest` |
| `share-plan-epoch`: the stage update writes epoch 1 | `stage_share_is_honest` |
| `share-plan-split`: the promote update uses the user id as split id | `promote_staged_split_is_honest` |
| `possession-classify-store`: a lost challenge race reports `Stored` | `store_challenge_is_honest` |
| `possession-classify-attempt`: a corrupt attempt reports `Missing` | `attempt_consumption_is_honest` |
| `possession-classify-grant`: a failed grant store reports `Stored` | `grant_store_is_honest` |
| `possession-plan-key`: the challenge is stored under the value, not its key | `store_challenge_is_honest` |
| `webauthn-classify-start-share`: a missing share reports present | `auth_start_observation_is_honest` |
| `webauthn-classify-start-credential`: a corrupt credential reports present | `auth_start_observation_is_honest` |
| `webauthn-classify-store-lost`: a lost challenge race reports `Stored` | `auth_start_store_is_honest` |
| `webauthn-classify-consume`: a corrupt attempt reports `Missing` | `attempt_consumption_is_honest` |
| `webauthn-classify-update`: a zero-row update reports `Updated` | `credential_update_guard_is_honest` |
| `webauthn-classify-account`: a rotating account reports an active epoch | `finish_account_is_honest` |
| `webauthn-classify-persist`: a zero-row write reports `Persisted` | `credential_persist_is_honest` |
| `webauthn-classify-uniqueness`: an unreadable lookup reports `Unique` | `uniqueness_is_honest` |
| `webauthn-classify-release`: a corrupt share reports `Decoded` | `share_release_is_honest` |
| `webauthn-plan-select-share`: the share read names the wrong account | `auth_start_observation_is_honest` |
| `webauthn-plan-grant-key`: the grant is stored under the value, not its key | `grant_store_is_honest` |
| `webauthn-plan-persist-user`: the credential write names another account | `credential_persist_is_honest` |
| `peek-classify`: a stored grant is reported absent | `peek_grant_is_honest` |
| `account-classify`: a rotating account reports an active epoch | `enrollment_account_is_honest` |
| `account-gate`: the commitment length ignores the epoch/rotation gate | `enrollment_account_is_honest` |
| `webauthn-backfill-plan-id`: a backfill write names the user id as its credential id | `backfill_run_names_the_rows` |
| `rate-classify`: a limited counter reports `Admitted` | `rate_limit_is_honest` |
| `rate-plan-key`: the counter is incremented at the empty key | `rate_limit_is_honest` |

## Real-store conformance

`vela-server/src/recovery/conformance.rs` runs the real executors on turso and
sled through a fault-injecting wrapper. Each case compares the result with the
Rust mirror.

- **Redemption:** 24 bounded states, 124 cases (62 faulted), plus 2 for an
  empty commitment. Schema check: the modelled `users`/`devices` columns exist
  and a duplicate device id is rejected.
- **Recovery share:** 12 bounded `users` states covering absence, epoch
  mismatch, rotation, an active share or split, and every candidate shape.
  144 cases (72 faulted), every statement and every read fault point. For
  `GetShareIo` the test also compares the decoded share bytes, split id and
  normalized epoch.
- **Possession:** 25 bounded states over the `users` row (absence, share,
  missing/valid/corrupt commitment, epoch, rotation), the exact attempt slot
  (absent, valid with matching or mismatched bindings, undecodable) and the
  grant key (absent or present). 92 cases (60 faulted), every SQL and store
  fault point. The test also compares the challenge-side epoch, the decoded
  commitment bytes, the stored attempt bindings and the issued grant id.
- **WebAuthn:** 9 bounded `users` shapes (absence, share present/absent, a
  decodable credential whose id agrees or disagrees with the indexed column,
  an absent or undecodable credential, rotation, a missing share that does not
  decode, and a non-default epoch), 3 attempt slots (absent, valid with the
  exact bindings, undecodable), 3 registration slots (absent, valid,
  undecodable) and 2 grant shapes. 437 cases (277 faulted), every SQL and store
  fault point of every method. The seeded stored credential, attempt envelope
  and registration state are real values built through the same WebAuthn types
  the handlers decode. The test also compares the split id side channel, the
  decoded released share bytes, the issued grant id, and the full `users` row
  including the credential-id index. Schema check: the six modelled columns
  exist and `recovery_webauthn_cred_id` rejects a duplicate.

- **Pre-driver, backfill and rate limits:** 8 `users` shapes for the preflight
  account read, a present/absent/undecodable grant, 5 backfill user shapes,
  and 9 limiters at three preseed levels. 23 cases for the reads and backfill
  (11 with an injected failure, every SQL and store fault point) plus 54
  rate-limit cases (27 with an injected store failure, every counter). The
  test compares the observation, the decoded grant, the preflight view's four
  fields, the backfilled credential ids and the counter values with the Rust
  mirror.

No executor was found dishonest.

## Rust changes

- `EnrollDeviceIo` holds `RecoverySql` and `RecoveryKv` instead of
  `&AppState`.
- The four recovery-share I/O structs hold `RecoverySql` instead of
  `&AppState`; their methods run `share_store` plans through the same
  render/run/classify loop.
- `InitiateProofIo` holds `RecoverySql`/`RecoveryKv`; `RecoverProofIo` holds
  them plus the raw store and the legacy-proof gate. Their methods run
  `possession_store` plans through the same loop.
- `InitiateIo`, `RecoverIo`, `RegisterStartIo` and `RegisterFinishIo` hold
  `RecoverySql`/`RecoveryKv` (plus the `AppState` the WebAuthn ceremony and the
  rate limiters need) and run `webauthn_store` plans through the same loop.
  Their methods are `pub(super)` and have `#[cfg(test)]` constructors and
  side-channel accessors for conformance.
- `auth_start_store`, `registration_start_store`, `auth_finish_update` and
  `registration_persist` split their ceremony-dependent serialization from the
  plan/run/classify write (`write_auth_state`, `write_registration_state`,
  `write_updated_credential`, `persist_credential_json`), so conformance can
  exercise the write with a fault while the ceremony result stays an input.
- `RecoveryKv` gained `exists`, `set_nx`, `set_ex` and `get`, and `Rendered`
  gained `KvExists`, `KvSetNx`, `KvSetEx`, `KvGet` and `KvIncr`.
- `observe_enroll_grant` runs through `plan_peek_grant`; a
  `pub(super)` entry point takes any store so conformance can inject a fault.
- `post_enroll_device`'s account read is a `plan_enrollment_account` query
  classified by the extracted gate; the four facts are copied from the
  extracted view. The commitment is decoded only when the epoch/rotation gate
  is open, exactly as before.
- `backfill_webauthn_cred_ids` runs the extracted scan and per-row write plans;
  a failed update is still logged and the remaining rows still run.
- The nine recovery limiter functions in `rate_limit.rs` run their extracted
  plans through `recovery_window`; `check` keeps its old body for the other
  limiters. Keys, windows, limits and the refusal text are unchanged.
- The insert timestamp can be injected for tests. Production still uses the
  current time inside the insert.
- The issued possession grant id and the drawn WebAuthn attempt id and grant id
  can be injected for conformance. Production still draws fresh v4 ids exactly
  when each is issued.
- `observe_recovery_share`, `observe_recovery_credential`,
  `observe_auth_state`, `store_auth_state`, `store_register_state`,
  `take_register_state`, `update_recovery_passkey_if_current` and
  `assert_credential_not_registered_elsewhere` are replaced by
  `recovery/sql.rs` row views and plan runners; their behaviour, statuses,
  messages and ordering are unchanged.
- `vela-server` gained a `webauthn-rs-core` dev-dependency so conformance can
  build a real stored passkey from the public credential types.
- SQL text, parameters, keys, statuses, messages and ordering are unchanged.

## Assumptions and limits

- Each operation is atomic, requests serialize, and store TTLs expire as
  configured.
- WebAuthn ceremony results (challenge and registration states, assertion
  results, `Passkey::update_credential`) are inputs; the model trusts that a
  serialized ceremony state decodes and that a serialized passkey round-trips.
- The credential-id index is modelled as one holder per credential id, which
  the `UNIQUE` index on `recovery_webauthn_cred_id` enforces.
- Not covered: none of the SQL/store I/O in the recovery handlers remains
  outside a plan. The four-field adapter from the extracted
  `EnrollmentAccountView` to the driver's `EnrollmentAccountFacts` is a
  structural copy, checked by conformance, not extracted.
- The startup backfill is best-effort: a failed `UPDATE` is logged and the
  remaining rows still run; the model states exactly that (the landed list is
  the plan's writes minus the failed ones).
- TTL expiry and fixed-window boundaries are abstracted as scheduler choices.

## Reproduction

```bash
cd serverVELA/vela-recovery-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh     # chains verify-fstar-recovery-executors.sh
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server --lib recovery::conformance
```

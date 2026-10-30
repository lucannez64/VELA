# Recovery executor honesty against a store model (F-1)

## Claim

The recovery drivers assume their executor objects report the truth about what
their key-value and SQL operations did. That assumption is proved against a
store model, for every starting state and every failing operation, and checked
against the real stores (turso and sled), for:

- **device redemption:** `EnrollDeviceIo`
  (`serverVELA/vela-server/src/recovery/enroll_device.rs`);
- **recovery share:** `PutShareIo`, `FinalizeShareIo`, `GetShareIo` and
  `DeleteShareIo` (`serverVELA/vela-server/src/recovery/mod.rs`).

The remaining recovery executor families are not covered yet: possession
(`InitiateProofIo`, `RecoverProofIo`) and WebAuthn (`InitiateIo`, `RecoverIo`,
`RegisterStartIo`, `RegisterFinishIo`).

## Design

Every executor method is a thin loop (plan → render → run → classify) over pure
pieces. The redemption pieces live in
`vela-recovery-policy/src/redemption_store.rs`; the recovery-share pieces live
in `vela-recovery-policy/src/share_store.rs`.

Redemption statements:

- `TakeGrant { key }`: an atomic get-and-delete of
  `recovery:enroll_grant:{user}:{grant}`.
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

`render` and `grant_key` give the exact SQL, parameters and key used before,
pinned byte for byte by unit tests.

## Exact theorems

`Vela_recovery_policy_redemption_lemmas.fst` and
`Vela_recovery_policy_share_lemmas.fst`, for every starting state, row and
fault point:

- **Redemption operations:** `take_grant_is_honest`, `insert_device_is_honest`,
  `authority_observation_is_honest` and `restore_grant_is_honest`.
- **Recovery-share operations:** `stage_share_is_honest`,
  `promote_staged_split_is_honest`, `delete_share_is_honest`,
  `stage_account_is_honest`, `finalize_account_is_honest` and
  `read_share_is_honest`. Each observation equals what the operation did to the
  modelled row; a failure changes nothing.
- **Facts the drivers rely on:**
  - redemption: `take_match_is_the_stored_grant`, `take_is_single_use`,
    `inserted_device_is_owned_and_guarded`, `restored_grant_is_live`;
  - recovery share: `staged_candidate_is_exact`, `promoted_split_is_active`,
    `deleted_share_is_cleared`, `not_staged_keeps_state`.
- **Vectors:** 7 redemption `vector_*` lemmas and 7 recovery-share
  `vector_share_*` lemmas, shared with the Rust mirror
  (`redemption_model.rs`).

Each module is checked in its own process under 700 MB, `--z3rlimit 200`, no
admits. The recovery-share modules take 35–44 s each; the redemption modules
are unchanged at 39–47 s.

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

No executor was found dishonest.

## Rust changes

- `EnrollDeviceIo` holds `RecoverySql` and `RecoveryKv` instead of
  `&AppState`.
- The four recovery-share I/O structs hold `RecoverySql` instead of
  `&AppState`; their methods run `share_store` plans through the same
  render/run/classify loop.
- The insert timestamp can be injected for tests. Production still uses the
  current time inside the insert.
- SQL text, parameters, keys, statuses, messages and ordering are unchanged.

## Assumptions and limits

- Each operation is atomic, requests serialize, and store TTLs expire as
  configured.
- Not covered yet:
  - the read-only grant check before redemption (`observe_enroll_grant`);
  - `post_enroll_device`'s account read before redemption;
  - the possession and WebAuthn executor families;
  - the rate limiters.

## Reproduction

```bash
cd serverVELA/vela-recovery-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh     # chains verify-fstar-recovery-executors.sh
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server --lib recovery::conformance
```

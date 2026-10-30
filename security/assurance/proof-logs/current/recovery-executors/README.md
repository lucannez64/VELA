# Recovery device-redemption executor against a store model (F-1)

## Claim

The redemption driver assumes `EnrollDeviceIo`
(`serverVELA/vela-server/src/recovery/enroll_device.rs`) reports the truth
about what its key-value and SQL operations did. That assumption is now proved
against a store model, for every starting state, grant and failing operation,
and checked against the real stores (turso and sled). Verified on 8268c79.

The other recovery executor families are not covered yet: possession
(`InitiateProofIo`, `RecoverProofIo`), recovery share (`PutShareIo`,
`FinalizeShareIo`, `GetShareIo`, `DeleteShareIo`) and WebAuthn (`InitiateIo`,
`RecoverIo`, `RegisterStartIo`, `RegisterFinishIo`).

## Design

The executor's four effect methods are thin loops (plan → render → run →
classify) over pure pieces in `vela-recovery-policy/src/redemption_store.rs`.
The statements are:

- `TakeGrant { key }`: an atomic get-and-delete of
  `recovery:enroll_grant:{user}:{grant}`.
- `InsertDevice { .., epoch, guard }`: `INSERT … SELECT … WHERE EXISTS` over
  the user's id, key epoch and rekey state, plus a guard:
  - `Credential { credential_id }` for a WebAuthn grant;
  - `Commitment` for a possession grant.
- `SelectAuthority { user }`: reads the recovery credential id and
  authentication hash.
- `PutGrant { key, value, grant }`: restores the grant with a 600 s TTL.

`render` and `grant_key` give the exact SQL, parameters and key used before,
pinned byte for byte by unit tests.

## Exact theorems

`Vela_recovery_policy_redemption_lemmas.fst`, for every starting state, grant
and fault point:

- **Operations:** `take_grant_is_honest`, `insert_device_is_honest`,
  `authority_observation_is_honest` and `restore_grant_is_honest`. Each
  observation equals what the operation did to the modelled stores. A failure
  changes nothing.
- **Facts the driver relies on:**
  - `take_match_is_the_stored_grant`;
  - `take_is_single_use`;
  - `inserted_device_is_owned_and_guarded`: a device is inserted only for the
    owner, at the current epoch, outside rotation, with the guard holding;
  - `restored_grant_is_live`.
- **Vectors:** 7 `vector_*` lemmas, shared with the Rust mirror
  (`redemption_model.rs`).

Every module is checked in its own process under 600 MB, `--z3rlimit 200`, no
admits: `Redemption_store` 35 s, `redemption_model` 37 s, `redemption_lemmas`
54 s.

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

## Real-store conformance

`vela-server/src/recovery/conformance.rs` runs the real `EnrollDeviceIo` on
turso and sled through a fault-injecting wrapper. Each case compares the
result with the Rust mirror.

- **States:** 24 bounded states, covering:
  - every grant shape: absent, matching, and possession, epoch or credential
    mismatch;
  - 8 user shapes;
  - empty and populated device tables;
  - both guards.
- **Cases:** 124, 62 of them with an injected failure, plus 2 for an empty
  commitment.
- **Schema check:** the columns the model uses exist, and a duplicate device
  id is rejected.

The executor picks a random device id, so its duplicate-id branch is covered
by the theorem and the schema check, not by an executor case. No executor was
found dishonest.

## Rust changes

- `EnrollDeviceIo` holds `RecoverySql` and `RecoveryKv` instead of
  `&AppState`.
- The insert timestamp can be injected for tests. Production still uses the
  current time inside the insert.
- SQL text, parameters, keys, statuses, messages and ordering are unchanged.

## Assumptions and limits

- Each operation is atomic, requests serialize, and the grant TTL expires as
  configured.
- Not covered yet:
  - the read-only grant check before redemption (`observe_enroll_grant`);
  - `post_enroll_device`'s account read before redemption;
  - the rate limiters.

## Reproduction

```bash
cd serverVELA/vela-recovery-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh     # chains verify-fstar-recovery-executors.sh
cd .. && ~/.local/opt/vela-tools/bin/vela-heavy cargo test -p vela-server --lib recovery::conformance
```

# Device pairing driver (F*)

This evidence directory backs the pure invitation/rendezvous decisions
extracted from

- `serverVELA/vela-enrollment-policy/src/pairing_driver.rs`;
- the rewired handlers `serverVELA/vela-server/src/device/invitation.rs` and
  `serverVELA/vela-server/src/device/rendezvous.rs`;
- the focused gate
  `serverVELA/vela-enrollment-policy/verify-fstar-pairing-driver.sh`, invoked
  from the crate's `verify-fstar.sh`.

Base commit: `5dda745329aa56991759102a7536fdb34d54ff2d`.
Worktree: `/home/hirew/.t3/worktrees/VELA/t3-04703409`.

## The gap this closes

`post_enrollment_package` / `get_enrollment_package`, `post_grant`,
`post_claim`, `post_complete` and `post_result` used to inline every
post-validation decision: the destructive package read classification, the
verified open policy, the historical claim-rejection precedence, the guarded
claim write classification, the grant/opener binding, the epoch/rekey
preflight, the verified completion policy, the single-use `take_live_pair`
outcome, the guarded insert outcome, the result record write, and the pending /
enrolled result classification. None of those decisions was extracted, and no
unbounded trace or concurrency theorem covered them.

The driver now owns every decision:

- invitation: a store is attempted only for a valid token and ciphertext
  length; a fetch performs at most one destructive read, and a missing,
  replayed or non-UTF-8 package is terminal with no success;
- grant opening: `plan_open` is the only path to the write;
- claim: `plan_claim` plus the historical per-field/conflict precedence, then
  the `set_ex_nx_if_live` outcome (`Inserted`/`GuardMissing`/`KeyExists`);
- completion: the grant/user/opener binding, `users` query, declared epoch,
  rekey permit, `plan_completion` (stored claim, active opener, signature over
  that claim, active account epoch), the destructive take equality, the guarded
  insert and the result record;
- result collection: `authorize_result` over the completed result or the live
  claim, including the signature-error precedence.

Statuses, messages, logged fields and the order of effects are unchanged,
except for the insert-error fix below. `invitation.rs`/`rendezvous.rs` now only
build the observation bundle, call the driver, and perform the returned effect;
the extracted driver is the only source of post-validation decisions.

## Bug found and fixed: an ambiguous insert error restored the ceremony

The historical `post_complete` restored the consumed grant **and** claim when
the guarded `INSERT` returned an error:

```rust
Err(error) => {
    state.store.set_ex_pair(&grant_key(..), &grant_bytes, &claim_key(..), &claim_bytes, ..)?;
    return Err(AppError::Internal(error.to_string()));
}
```

An `INSERT` error does not prove that no row committed (a connection drop after
commit is the standard example). Concrete sequence:

1. The opener validates a completion (stored claim present, opener signature
   verified, epoch active) and `take_live_pair` consumes the grant+claim.
2. The guarded `INSERT` commits the new device row; the SQL driver then reports
   an error (connection/protocol failure).
3. The old handler restores the exact grant and claim and returns 500.
4. The opener retries the completion. The restored pair passes every check
   again, the guarded insert commits, and a **second** device row is enrolled
   from the same claim/ceremony.

That breaks the target property "at most one completion / enrolled device per
grant". `vela_recovery_policy::driver` already treats `InsertObservation::Failed`
as terminal for exactly this reason. The pairing driver now does the same:
`DeviceInsertObservation::Failed -> Fail(InsertStorage)` with no restoration;
the grant and claim stay consumed, the status/message is unchanged, and the
client must start a new ceremony. A definite zero-row insert (`Skipped`, the
rotation guard) still restores, because it cannot have committed.

Regression test: `an_ambiguous_insert_error_consumes_the_ceremony` in
`src/pairing_driver.rs` (plus the updated
`an_insert_failure_never_claims_a_recorded_result`).

A second, liveness-only gap remains (reported, not fixed): if the **result
record write** fails after the device row committed, the joining device never
learns its `device_id` (`/result` now returns not-found because the claim is
consumed and the grant is gone). Nothing is enrolled twice; the user must start
a new ceremony. See "Open obligations".

## Contract and theorem statements

Focused extraction: `proofs/fstar/extraction-pairing-driver/` (19 selected
entry points plus 11 private decisions = 30 extracted functions, 30
effect/state postconditions, 24 preconditions). Per-request module:
`proofs/fstar/pairing-driver-lemmas/`. Composition:
`proofs/fstar/pairing-driver-composition/`.

`step` is total; every event after `Done` and every out-of-ceremony event is
`Idle`:

```fstar
val step : d:t_PairingDriver -> e:t_PairingEvent ->
  Pure t_PairingTransition
    (requires (pairing_state_is_sound d))
    (ensures (fun r ->
      pairing_effect_is_sound r.driver r.effect /\
      (pairing_state_is_sound d ==> pairing_state_is_sound r.driver)))
```

Provenance lemmas over every event list:

- `write_claim_requires_claim_policy`: a `WriteClaim` effect implies
  `claim_is_authorized (claim_facts observation)`, hence a live grant and no
  existing claim.
- `take_requires_completion_policy` / `take_implies_completion_facts`: a
  `TakeCeremony` effect implies the verified completion policy accepted a
  stored claim, an active opener, a verified signature over that claim, the
  user/opener bindings and an active matching epoch.
- `insert_requires_matched_take`: an `InsertDevice` effect implies the
  destructive take observed both compared byte strings equal.
- `redeem_complete_requires_present`, `missing_redeem_never_completes`: a
  package is only handed out after a present, UTF-8 observation; a missing or
  replayed token never completes a redemption.
- `store_complete_requires_stored`, `claim_complete_requires_inserted`: a
  terminal store/claim success only follows the corresponding reported success.
- `result_return_requires_proof` / `claim_return_requires_proof`: `Enrolled`
  implies a completed result record with a non-empty key and a verified
  signature; `Pending` implies a live claim with the same proof.
- `complete_success_implies_insert_and_record`: a completion success carries
  both the inserted row and the result record.

Headline per-ceremony theorems:

```fstar
invitation_trace_theorem : for every token observation and event list,
  sound final state /\ at most one complete and one failure effect

claim_trace_theorem : for every grant-live flag and event list,
  sound final state /\ at most one WriteClaim /\ at most one success/failure

completion_trace_theorem : for every grant observation and event list,
  sound final state /\ at most one TakeCeremony /\ at most one InsertDevice /\
  at most one success/failure /\
  (inserted ==> grant_present && claim_present && opener_active &&
                signature_verified && user_matches && opener_matches) /\
  (restored ==> failed && not inserted)

result_trace_theorem : for every event list,
  sound final state /\ at most one success/failure
```

Concurrent composition (`pairing_composition_theorem`, every schedule over
package store/redeem, claim, the completion account/preflight/take/insert/
result steps, result collection and arbitrary interleavings):

```fstar
let w = run_world initial schedule in
inv w /\
w.w_claim_authorizations <= 1 /\
w.w_enrollments <= 1 /\
w.w_enroll_after_enrolled = 0 /\
w.w_enroll_cross_account = 0 /\
w.w_enroll_without_signature = 0 /\
w.w_take_without_claim = 0 /\
w.w_pkg_double_redeem = 0 /\
w.w_package.p_version_redemptions <= 1 /\
w.w_grant.g_enrolled <= 1
```

Named consequences: `at_most_one_claim`, `at_most_one_enrollment`,
`no_cross_account_enrollment`, `no_unsigned_enrollment`,
`no_take_without_claim`, `at_most_one_redemption_per_version`.

Every counter is incremented at the point the *driver* authorizes the forbidden
effect, or (for the invitation) returns the package after a present
observation:

- `w_claim_authorizations` counts `WriteClaim` effects; `w_claim_records`
  counts the writes the model's atomic read-decide-write applies.
- `w_enroll_after_enrolled` counts `InsertDevice` while a row already exists.
- `w_enroll_cross_account` / `w_enroll_without_signature` count `InsertDevice`
  while the request's spawn-time account binding / signature observation was
  negative.
- `w_take_without_claim` counts `TakeCeremony` while the world has no stored
  claim.
- `w_pkg_double_redeem` counts a redeem completion after the stored version was
  already redeemed; `p_version_redemptions` is reset by a new store.

No counter is incremented by a modelled SQL/store guard refusing a write.

Witness schedules show: a full legitimate ceremony (one claim, one take, one
insert, one result, one redemption); a replayed completion that enrolls
nothing; a replayed claim authorizing no second write; a replayed redemption
returning nothing; a cross-account completion refused at the binding; an
unsigned completion refused by the verified policy.

## What depends on the driver vs on modelled SQL/store

Depends on the extracted driver (proved):

- token/length refusal, the destructive-read classification and
  at-most-one-redemption-per-request;
- the verified open policy, claim policy and completion policy, including the
  historical rejection precedence;
- the user *and* opener binding (not just the same account);
- the completion order: policy → destructive take → guarded insert → result
  record; no insert without a matched take, and no success without both the
  row and the record;
- terminality of storage observations and at-most-one success/failure;
- the result/pending classification under the claimed key's signature;
- the composition counters: at most one claim write authorization, at most one
  take/insert, no insert after an enrolled row, no cross-account insert, no
  unsigned insert, no take without a claim, and one redemption per stored
  version.

Modelled / assumed, not proved:

- the sled package cell is linearizable; a store creates a new package version
  and resets that version's redemption count, and a destructive read removes
  the live version atomically;
- the sled grant and claim records and the `take_live_pair` transaction are
  linearizable; the take consumes both exactly once;
- the SQL `users` query, the guarded `INSERT` and the sled result write report
  success/failure; a `Failed` insert is treated as possibly committed (safe),
  a `Skipped` insert as definitely not committed;
- the claim's `exists` read and `set_ex_nx_if_live` CAS are modelled as one
  atomic read-decide-write step, which is the store operation's linearization
  point; the observation supplied to the driver is the store state at that
  point;
- the opener's hybrid signature observation is honest: unforgeability and
  key-binding are the M13/Tamarin model's job, and the per-request lemma only
  proves the driver authorizes on `SignatureObservation::Verified` over the
  stored claim;
- the grant's owner and opener do not change during a trace (no transfer
  action), so the spawn-time comparison stays valid;
- account epochs and TTL expiry are constants outside the model; the 5-minute
  grant TTL and 15-minute package TTL are not modelled.

## Explicit assumptions, non-claims and open obligations

- No refinement theorem connects the Rust handlers to the F* trace. The
  handlers are reviewed to build the observation bundle, call the extracted
  functions and perform exactly the returned effect; that wiring is not
  mechanically refined.
- No proof of sled/Turso atomicity, durability, replication, crash/retry,
  clock/TTL expiry or multi-node visibility.
- No proof of hybrid-signature unforgeability, base64/UTF-8 edge cases, rate
  limiting, or the `vela_crypto` primitives. Those are Tamarin/CryptoVerif/
  Rust-test obligations.
- The composition's claim atomicity assumes the store's linearization point is
  the CAS, and its "no cross-account/unsigned/after-enrolled insert" counters
  assume the modelled observations are the handler's real ones.
- **Result-write liveness gap (reported, not fixed).** After the device row
  commits, `set_ex(result_key, ...)` can fail; the device is enrolled but the
  joining device cannot learn its id (the claim and grant are consumed, so
  `/result` returns not-found). A future change should write the result in the
  same durable unit as the insert, or add an opener-driven retry/recovery path.
  This does not enroll a second device and is out of the safety scope here.
- The grant-open driver is per-request only: every open targets a fresh random
  grant id, so there is no shared object and no interleaving property to
  compose. The composition therefore starts from one open grant.
- A package re-store overwrites the same token key and starts a new version;
  "at most one redemption" is per stored version, matching
  `pairing_model`'s one-successful-fetch-per-`StorePackage` property.

## Mutation checks

Six mutants are copies of the regenerated extraction under `/tmp/opencode`,
never committed; the checked-in extraction is the unmodified successful run.
Each mutant edits only the generated driver module and runs the composition
module; all six exit 1.

| Mutant | Change | Failure |
|---|---|---|
| `mutation-claim-guard.diff` | `on_claim_checked` treats `plan_claim`'s `Reject` as a write authorization | `claim_policy_refuses` (composition line 724): an existing claim now yields `WriteClaim`. `spawn_claim_inv` therefore cannot keep `w_claim_authorizations <= 1`. |
| `mutation-completion-binding.diff` | `begin_completion` drops the user/opener refusal and records both bindings as true | `spawn_complete_inv` (composition line 811): a cross-account request reaches the preflight with `f_user_matches = true` while its request fact is false. `w_enroll_cross_account` would increment. |
| `mutation-take-replay.diff` | `on_ceremony_taken` treats `TakeObservation_Missing` as a matched take | `completion_take_inv` (composition line 870): a second completion reaches `InFlight`. `w_enroll_after_enrolled` and `g_enrolled <= 1` fail. |
| `mutation-completion-signature.diff` | `on_completion_ready` passes `signature_verified = true` to the policy | `completion_preflight_inv` (composition line 848): the request's `signature_ok = false` is overridden. `w_enroll_without_signature` would increment. |
| `mutation-take-claim.diff` | `on_completion_ready` passes `claim_present = true` to the policy | `take_authorization_implies_claim` (composition line 712): a take without a stored claim. `w_take_without_claim` would increment. |
| `mutation-redeem-replay.diff` | `on_package_redeemed` treats `Missing` as a successful redemption | `redeem_completion_requires_present` (composition line 737): a replayed token completes. `w_pkg_double_redeem` and `p_version_redemptions <= 1` fail. |

Each mutant therefore removes a *driver decision*, not a modelled store guard;
the corresponding counter is load-bearing, not true by construction.

## Tests and gates

| Gate | Result | Log |
|---|---|---|
| `verify-fstar-pairing-driver.sh` | exit 0; root + driver + 2 proof modules verified | `focused-verify.log` |
| crate `verify-fstar.sh` (historical + pairing) | exit 0; historical extraction byte-identical, pairing modules verified | `full-verify.log` |
| `vela-enrollment-policy` tests | 13 lib + 5 fact-construction passed | `cargo-test-enrollment-policy.log` |
| `pairing_model` | 2 passed | `cargo-test-pairing-model.log` |
| `enrollment_ceremony_model` | 3 passed | `cargo-test-enrollment-ceremony-model.log` |
| `integration` | 68 passed | `cargo-test-integration.log` |
| `check-proof-boundary.py` | 14 artifacts, 249 selected postconditions | (command in `commands.txt`) |
| formal unittest suite | 50 passed | (command in `commands.txt`) |
| six driver mutants | all exit 1 | `mutation-*.log` |

F* 2025.10.06, Z3 4.13.3, hax 0.3.7. The composition runs with
`--z3rlimit 500`; its non-vacuity witnesses evaluate concrete schedules, so a
larger budget only makes Z3 search longer. The per-request module runs with
`--z3rlimit 16000`. No `admit`, `assume`, `axiom`, `--lax` or unreviewed
pragma. The source guard reports two extracted modules and two proof modules
with no escapes.

`focused-verify.log` was captured immediately before the final test-only
conformance test was added; its printed `src/pairing_driver.rs` hash therefore
predates that test block. The extraction and both proof modules are
byte-identical to the checked-in files (a fresh `cargo hax into` diff is
empty), and `source-hashes.txt` is authoritative for the committed tree. All
13 lib tests are recorded in `cargo-test-enrollment-policy.log`.

## Reproduction

From `serverVELA/vela-enrollment-policy`, with the environment in
`commands.txt`:

```
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-pairing-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh
```

The focused extraction is regenerated into
`proofs/fstar/extraction-pairing-driver/`; it is never mixed with the
historical `proofs/fstar/extraction/` artifact.

## Counts and hashes

See `counts.txt` and `source-hashes.txt`.

## Hosted reproduction

The [54b38b3 security workflow](https://github.com/lucannez64/VELA/actions/runs/40402764401) verified the pairing extraction,
per-request lemmas and composition, and ran the enrollment policy tests and the
full 68-test integration suite; all fifteen PR checks passed.
`hosted-54b38b3.log` holds the summary and hashes, which match the local run.

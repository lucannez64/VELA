# Possession-proof recovery drivers (F-2 increment)

Date: 2026-10-25
Parent: `4f3c2c4` (`End a revoked device's approved web sessions with it`)
Worktree: `/home/hirew/.t3/worktrees/VELA/t3-d7ac1fca`
Heavy-command wrapper: `~/.local/opt/vela-tools/bin/vela-heavy`
Target dir: `/home/hirew/.t3/worktrees/VELA/t3-700776df/target`

This increment owns only:

- `serverVELA/vela-recovery-policy` (new `src/possession_driver.rs`, tests,
  focused extraction and F* gates)
- `serverVELA/vela-server/src/recovery/possess.rs`
- this evidence directory

No global assurance file, manifest, correspondence table or CI file is edited.

## What changed

Both possession-proof handlers now delegate every post-preflight decision to
the pure drivers in `vela_recovery_policy::possession_driver`:

1. `begin_initiation` asks for the live-row observation.
2. `on_initiation_observed` calls the existing
   `proof_initiate_facts`/`plan_proof_initiation` policy and classifies a
   rejection with the historical status/message precedence (account absence,
   rotation pause, missing/corrupt commitment, missing share, attempt-id
   collision, fail-closed policy rejection).
3. `on_challenge_stored` classifies the atomic `set_ex_nx` outcome; a lost
   first-writer race is the historical 409 conflict.
4. `begin_proof_recover` asks for the rate-limit attempt count.
5. `on_attempt_counted` advances only on an admitted count.
6. `on_attempt_consumed` classifies the single-use `get_del` of the proof state
   (missing, corrupt, mismatched binding, matched) and never re-arms a consumed
   state.
7. `on_account_observed` classifies the live row (absent, freezing/rotation,
   missing or corrupt commitment, present) before any verification.
8. `on_proof_observed` calls the existing
   `possession_recover_facts`/`plan_possession_recovery` policy and issues the
   grant authority only for a verified proof at the live epoch.
9. `on_grant_stored` maps the single-use grant store outcome.

The handlers perform the effects (`users` query, commitment decode, `get_del`,
verification, `set_ex_nx`, grant store) and render the driver's failure class
with the existing HTTP statuses and messages. The share is not an effect of
either driver: there is no release variant in the effect language, and the only
grant-carrying effect carries an epoch only.

Behavior is otherwise unchanged: the initiation/response shapes, the
single-use attempt, the per-IP/per-user rate limits, the epoch/freezing/commitment
checks, the grant payload and the "never release the server share" property are
all preserved. The bounded conformance model
(`recovery_possession_model.rs`, depth 4) still passes against the real router,
schema and store.

## Rust postconditions (checked by hax/F*)

The focused gate selects 11 functions with contracts: `begin_initiation`,
`step_initiation`, `on_initiation_observed`, `on_challenge_stored`,
`begin_proof_recover`, `step_proof_recover`, `on_attempt_counted`,
`on_attempt_consumed`, `on_account_observed`, `on_proof_observed` and
`on_grant_stored`.

| Function | `requires` / `ensures` |
|---|---|
| `begin_initiation` | effect `Observe`; state sound; stage `Observe`; no authority. |
| `step_initiation` | sound input state; effect sound; soundness preserved. |
| `on_*` initiation wrappers | same postcondition through `step_initiation`. |
| `begin_proof_recover` | effect `CountAttempt`; state sound; stage `Attempt`; all authority flags false; no share release. |
| `step_proof_recover` | sound input; effect sound; soundness preserved; no share release. |
| `on_*` recovery wrappers | same postcondition through `step_proof_recover`. |

`proof_recover_effect_is_sound` requires, for `IssueGrant`:

- stage `Issue`, counted attempt, consumed proof state, matched user/attempt
  binding, verified proof;
- live account present, epoch active, non-empty commitment;
- `permit.epoch = observed_recovery_epoch(stored_epoch) = attempt_epoch`;
- grant issued, not yet stored.

`proof_recover_state_is_sound` additionally states: consumption implies a
counted attempt; a match flag implies consumption; verification implies a
matched consumed attempt; a grant implies a verified, matched, current-epoch,
non-empty-commitment observation; a stored grant is terminal.

These are conditional on the input state, which is a genuine inductive
invariant: the hand-written F* module proves it independently and
unconditionally for every trace starting at the extracted `begin_*`.

## Hand-written F* per-request lemmas

Module:
`serverVELA/vela-recovery-policy/proofs/fstar/possession-driver-lemmas/Vela_recovery_policy_possession_driver_lemmas.fst`

It imports the extracted
`Vela_recovery_policy.Possession_driver.step_*` and does not reimplement the
transition machine. It defines independent `initiation_trace_sound` and
`trace_sound` predicates, proves them equal to the extracted Rust predicates,
then proves by induction over arbitrary event lists:

- `initiation_trace_sound_matches_rust`, `initiation_begin_sound`,
  `initiation_step_sound`, `run_initiation`, `count_challenge_stores`;
- `initiation_store_requires_authority`; `no_store_from_store`;
  `initiation_store_count_le_one` (at most one stored challenge per request);
- `initiation_trace_theorem`;
- `trace_sound_matches_rust`, `begin_sound`, `step_sound`, `run`,
  `count_grants`, `last_effect`;
- `plan_grant_requires_verified` — the checked possession policy grants only
  when the proof observation was verified;
- `grant_effect_origin` — an `IssueGrant` effect is only a response to a
  verified `ProofObserved` event, from stage `Verify`, with a matched consumed
  attempt and post-state stage `Issue` carrying a non-empty current-epoch
  commitment;
- `grant_effect_epoch` — the permit epoch is the live observed epoch, equals the
  consumed attempt epoch and is at least `INITIAL_EPOCH`;
- `no_grant_while_freezing` — a live observation with `rekey_state` set cannot
  emit a grant;
- `no_grant_after_revocation` — a missing or corrupt staged commitment cannot
  emit a grant;
- `no_effect_releases_share`, `step_never_releases_share` — the share is not an
  effect (the effect language has no release constructor);
- `no_grant_after_issue`, `issue_suffix_no_grants` — after an issued grant, any
  unbounded suffix issues zero further grants;
- `step_after_complete`, `complete_suffix_inert` — after a stored grant, every
  event is inert;
- `grant_count_le_one` — at most one grant per driver instance for any event
  list;
- `no_second_grant_after_prefix` — the all-pairs corollary;
- `proof_recover_trace_theorem` — final soundness, grant count ≤ 1, and a grant
  state carries a single-use matched verified non-empty current-epoch proof;
- reachability witnesses: initiation success/collision/unavailable; recovery
  success, grant-storage failure, budget refusal, missing attempt, stale
  envelope epoch rejection, freezing, commitment revocation and an unverified
  proof. All are proved from the actual extracted `begin_*`.

## Concurrent composition

Module:
`serverVELA/vela-recovery-policy/proofs/fstar/possession-driver-composition/Vela_recovery_policy_possession_driver_composition.fst`

The world is `{ proof_state : bool; budget : nat; grants : nat; reqs : list
driver }`. A schedule is an arbitrary list of actions: spawn a request, count
an attempt, consume the proof state, deliver the live-account / proof /
grant-store observation to any request. The model mirrors the template:

| Real effect | Model |
|---|---|
| sled rate limiter | `Count` spends one unit of a shared budget and is the only way to reach `Consume` |
| atomic `Store::get_del` | `Consume` sees the state iff `proof_state` and clears it in the same step |
| `users` row / commitment / verification | schedule chooses the observation delivered in the same step |
| single-use grant store | `Prove` converts the held token into one grant when the driver emits `IssueGrant` |

Invariant:

```
all_sound reqs
∧ b2n proof_state + grants + held reqs ≤ 1
∧ budget + counted reqs ≤ k
```

Headline theorem:

```
one_proof_state_at_most_one_grant (k: nat) (schedule: list action):
  let w = run_world (initial k) schedule in
  w.grants ≤ 1 ∧ counted w.reqs ≤ k ∧ w.budget ≤ k
```

Non-vacuity witnesses, checked one world step at a time with `run_cons`:
one grant reachable; two racing requests write exactly one grant; with budget 1
the second request is refused; a stale attempt epoch issues no grant; freezing
issues no grant; an unverified proof issues no grant.

Assumptions (not proved here): `get_del` is linearizable; the handler performs
exactly the effect the driver returns; the proof state was created once by an
admitted initiation; each observation reaches the driver in the same step as
its effect. SQL/row semantics and observation origins remain outside this
module.

## Mutation check

`mutation-full.log` and `mutation-composition.log` are produced from a copy of
the extracted driver (never committed) with a plausible rate-limit bug:
`AttemptBudgetObservation::Limited` is treated as admitted and moves the driver
to `Consume` with `budget_counted = true`.

- `mutation-full.log`: the unmodified lemma module rejects the mutation at the
  limited-attempt reachability witness (line 745).
- `mutation-composition.log`: because that witness is exactly the statement the
  bug falsifies, this run uses a copy of the lemma module with only that
  non-vacuity witness omitted; all trace lemmas and the composition theorem are
  unchanged. The composition proof then fails at `world_step_inv`
  (`Assertion failed`, line 306), because a refused request increases the
  counted total without spending budget.

This shows the composition theorem depends on the attempt budget being spent
before consumption. The mutated extraction and lemma copies live only under
`/tmp/possession-mutation-final/` and are not part of the commit.

## Tests vs proof

- `cargo-test-recovery-policy.log`: 7 existing unit tests, 8 fact tests, 12
  existing redemption-driver tests and 17 new possession-driver tests
  (stage × event coverage, out-of-order inertness, BFS reachable-state
  invariants, one grant per request, no grant without a verified current-epoch
  proof, no share release, initiation precedence and lost-race handling).
- `cargo-test-server-integration.log`: the full 65-test HTTP integration suite
  after the handler rewiring.
- `cargo-test-recovery-possession-model.log`: the bounded possession handler /
  database trace model (depth 4).
- `cargo-test-recovery-lifecycle-model.log`: the bounded lifecycle model.
- `fstar-full-verify.log`: one `./verify-fstar.sh` run — the historical
  90-contract extraction and F* check, the existing enrollment-redemption
  driver gate, and this possession-driver gate. Tests and proof are separate
  evidence; neither substitutes for the other.

## Bugs found

No new bug was exposed by this refactor. In particular:

- the atomic `get_del` remains the single-use linearization point, and the
  driver records a consumed state as terminal on every failure;
- the rate limiter is still charged exactly once per recovery request, before
  the proof state is touched;
- freezing/rotation and commitment deletion are terminal/refusing before any
  grant, and epoch mismatch is rejected by the checked policy;
- the server share is never released on the possession path (there is no such
  effect, and the response contains only `key_epoch` and `recovery_grant`).

The historical behavior touched by the refactor is preserved, including the
commitment-corrupt/internal-error precedence and the lost `set_ex_nx` race
conflict.

## Scope and open obligations

- Scope is one request/driver instance for the per-request module and one
  shared proof state for the composition module.
- Not modelled/proved: `get_del` atomicity, `set_ex_nx` atomicity, SQL row and
  guard semantics, the cryptographic verification itself, store TTL/expiry,
  grant-store success, and crash/retry behavior. They enter as observations.
- The rate-limit window/TTL implementation is modelled only as an atomic budget
  decrement; the two real limiter keys (IP+user and user) are still effectful
  glue.
- The proof state is assumed to have been created once by an admitted
  initiation; initiation and recovery are not composed in one world.
- No full F-2 closure is claimed.
- The historical 90-contract extraction is byte-identical after the focused
  gates (`git status` on `proofs/fstar/extraction/` is clean).

## Toolchain / commands

- hax 0.3.7, F* 2025.10.06, Z3 4.13.3.
- Focused extraction and argv: `verify-fstar-possession-driver.sh`.
- Full F* argv and hashes: `fstar-full-verify.log` and `source-hashes.txt`.

## Hosted reproduction

The [7a6d108 security workflow](https://github.com/lucannez64/VELA/actions/runs/40149234823) ran this gate; all fifteen PR checks
passed. `hosted-7a6d108.log` is its summary and matches the local hashes.

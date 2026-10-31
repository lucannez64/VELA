# WebAuthn recovery drivers (F-2 increment)

Date: 2026-10-26
Parent: `5dda745` (`Record hosted reproduction of the device revocation driver`)
Worktree: `/home/hirew/.t3/worktrees/VELA/t3-e2171f5c`
Branch: `t3/webauthn-recovery-driver`
Heavy-command wrapper: `~/.local/opt/vela-tools/bin/vela-heavy`
Target dir: `/home/hirew/.t3/worktrees/VELA/t3-700776df/target`

This increment owns only:

- `serverVELA/vela-recovery-policy` (new `src/webauthn_driver.rs`, new
  `tests/webauthn_driver.rs`, a new focused extraction, new F* lemma and
  composition modules, and a new verify runner wired into `verify-fstar.sh`)
- `serverVELA/vela-server/src/recovery/{webauthn,initiate,recover}.rs`
  (the WebAuthn recovery handlers)
- this evidence directory

No global assurance file, manifest, correspondence table or CI file is edited.
The historical extraction (`proofs/fstar/extraction/`), the enrollment-driver
extraction and the possession-driver extraction are untouched.

## What changed

The four WebAuthn recovery requests now delegate every post-validation decision
to the pure drivers in `vela_recovery_policy::webauthn_driver`:

1. `begin_registration_start` asks for the stored-credential observation.
2. `on_registration_start_observed` classifies account absence and a corrupt
   stored credential, and authorizes the ceremony only for a usable account.
3. `on_registration_ceremony_started` classifies the WebAuthn ceremony start.
4. `on_registration_start_stored` classifies the `set_ex` state write.
5. `begin_registration` asks for the registration rate-limit count.
6. `on_registration_attempt_counted` advances only on an admitted count.
7. `on_registration_state_consumed` classifies the single-use `get_del` of the
   registration state (missing, corrupt, present).
8. `on_registration_verified` classifies `finish_passkey_registration`.
9. `on_credential_looked_up` classifies the cross-account uniqueness lookup and
   calls the existing `plan_registration` policy; `PersistCredential` is emitted
   only for a `Register` permit.
10. `on_credential_persisted` classifies the guarded `UPDATE` (persisted,
    zero-row account absence, serialization failure, storage failure).
11. `begin_auth_start` asks for the availability/credential/slot observation.
12. `on_auth_start_observed` calls the existing
    `initiate_facts`/`plan_initiation` policy and classifies the historical
    rejection precedence (account, share, credential, corrupt credential,
    attempt collision, fail-closed policy rejection).
13. `on_auth_ceremony_started` classifies `start_passkey_authentication`.
14. `on_auth_start_stored` classifies the atomic `set_ex_nx` write; a lost race
    is the historical 409 conflict.
15. `begin_auth_finish` asks for the rate-limit attempt count.
16. `on_auth_finish_attempt_counted` advances only on an admitted count.
17. `on_auth_finish_context_observed` classifies share/credential availability
    and the presence of the request's attempt id *before* the challenge is spent.
18. `on_auth_attempt_consumed` classifies the atomic `get_del` of the
    attempt-bound challenge (missing, corrupt, binding mismatch, challenge
    credential replaced, matched).
19. `on_auth_assertion_observed` classifies the assertion result and calls the
    existing `credential_update_facts`/`plan_credential_update` policy; only a
    `Update` decision emits `UpdateCredential`, and `Keep` proceeds straight to
    the live row.
20. `on_auth_credential_updated` classifies the conditional credential write.
21. `on_auth_account_observed` calls the existing
    `recover_facts`/`plan_recovery` policy and emits the single `ReleaseGrant`
    authority only for a `Release` decision, preserving the historical
    accounting precedence on rejection.
22. `on_auth_share_observed` classifies the staged share decode.
23. `on_auth_grant_stored` maps the single-use grant store outcome.

The handlers perform the effects (`users` queries, credential JSON decode,
WebAuthn ceremony start/finish, `get_del`, `set_ex`/`set_ex_nx`, the conditional
`UPDATE`, the share base64 decode, the grant store and the rate-limit counters)
and render the driver's failure class with the historical HTTP status and
message.

### Share release (scope adjustment)

The brief's per-request theorem includes "the recovery share is never an
effect". That statement matches the possession path, not this one: the WebAuthn
assertion path exists to release Share 2. The adjusted theorem is:

- the driver has exactly one share-releasing effect, `ReleaseGrant`;
- it is emitted only from the checked `plan_recovery` `Release` decision and
  carries only the live epoch, never share bytes;
- the share is not returned unless the driver reaches `Complete` after the
  single-use grant store succeeded;
- every other effect of all four drivers is share-free.

This is stated and proved, not merely inspected: `auth_finish_effect_releases_share`
returns true only for `ReleaseGrant`, and `only_release_effect_releases_share`
proves that exactly that effect is the share-carrying one.

## Rust postconditions (checked by hax/F*)

The focused gate selects 27 functions with contracts:

| Driver | Selected functions |
|---|---|
| registration start | `begin_registration_start`, `step_registration_start`, `on_registration_start_observed`, `on_registration_ceremony_started`, `on_registration_start_stored` |
| registration finish | `begin_registration`, `step_registration`, `on_registration_attempt_counted`, `on_registration_state_consumed`, `on_registration_verified`, `on_credential_looked_up`, `on_credential_persisted` |
| authentication start | `begin_auth_start`, `step_auth_start`, `on_auth_start_observed`, `on_auth_ceremony_started`, `on_auth_start_stored` |
| authentication finish | `begin_auth_finish`, `step_auth_finish`, `on_auth_finish_attempt_counted`, `on_auth_finish_context_observed`, `on_auth_attempt_consumed`, `on_auth_assertion_observed`, `on_auth_credential_updated`, `on_auth_account_observed`, `on_auth_share_observed`, `on_auth_grant_stored` |

Each `step_*` requires its driver state to be sound and ensures every emitted
effect agrees with the produced state and soundness is preserved. The
independently written `af_trace_sound` in F* states, in particular:

- a matched consumption implies a counted attempt; a user/attempt/credential
  match flag implies a consumption; a verified assertion implies a matched
  consumed challenge;
- `ReleaseGrant` requires: stage `Release`, counted attempt, consumed
  user/attempt-bound challenge, challenge/assertion/stored credential chain,
  verified user-verified assertion, a completed metadata update when one was
  requested, a present share, an active non-rotating account, and a normalized
  live epoch `>= INITIAL_EPOCH`; the permit epoch is exactly
  `observed_recovery_epoch(stored_epoch)`;
- a decoded share implies an issued grant; a stored grant implies a decoded
  share and a terminal `Done`;
- `Complete` is the only success, and a failure never has a stored grant.

`registration_state_is_sound` similarly makes a stored credential imply a
consumed single-use state, a valid ceremony, uniqueness and a policy permit.
The two small initiation invariants make a stored challenge imply `authorized`
and terminal `Done`, and the ceremony/state effects at most once.

## Hand-written F* per-request lemmas

Module:
[`proofs/fstar/webauthn-driver-lemmas`](extractions/Vela_recovery_policy_webauthn_driver_lemmas.fst).

The module imports the extracted transition functions and does not reimplement
the transition machine. It defines four independent invariants
(`rs_trace_sound`, `reg_trace_sound`, `as_trace_sound`, `af_trace_sound`),
proves each equal to the extracted Rust predicate, then proves by induction over
arbitrary event lists:

- registration start: `rs_begin_sound`, `rs_step_sound`, `run_registration_start`,
  `registration_start_ceremony_requires_authority`, `no_ceremony_from_ceremony`,
  `no_store_from_store`, `registration_start_ceremony_count_le_one`,
  `registration_start_store_count_le_one`, `registration_start_trace_theorem`
  (sound final state; at most one ceremony; at most one `set_ex`; a stored state
  is authorized and terminal);
- registration finish: `reg_begin_sound`, `reg_step_sound`, `run_registration`,
  `registration_persist_requires_policy` (a `PersistCredential` effect implies
  the real `plan_registration` facts and `Register` decision),
  `no_persist_from_persist`, `registration_persist_count_le_one`,
  `registration_trace_theorem` (at most one credential write; a stored
  credential implies a consumed state, a valid ceremony and uniqueness);
- authentication start: `as_begin_sound`, `as_step_sound`, `run_auth_start`,
  `auth_start_store_requires_policy`, `no_auth_store_from_store`,
  `auth_start_store_count_le_one`, `auth_start_trace_theorem` (at most one
  challenge store; a stored challenge is authorized);
- authentication finish: `af_begin_sound`, `af_step_sound`, `run_auth_finish`,
  `count_auth_finish_releases`, `last_auth_finish_effect`,
  `plan_release_requires_authorization` (the checked policy's `Release` implies
  every fact it was built from), `release_effect_origin` (a `ReleaseGrant` is
  only a response to an `AccountObserved` from stage `Account`, with every
  release fact and the permit epoch equal to the normalized live epoch),
  `no_release_while_freezing`, `no_release_after_credential_replacement`,
  `no_release_on_replaced_challenge`, `no_release_without_share`,
  `release_requires_verified_assertion`, `only_release_effect_releases_share`,
  `no_release_after_issue`, `release_suffix_no_releases`,
  `step_after_complete`, `complete_suffix_inert`,
  `auth_finish_release_count_le_one`, `no_second_release_after_prefix`, and the
  headline `auth_finish_trace_theorem`.

Headline per-request statement (over the actual extracted driver):

```
auth_finish_trace_theorem (events):
  let d = run_auth_finish_from_begin events in
  af_trace_sound d /\
  count_auth_finish_releases_from_begin events <= 1 /\
  (d.f_grant_issued ==>
    d.f_attempt_consumed /\ d.f_user_matches /\ d.f_attempt_matches /\
    d.f_challenge_credential_matches /\ d.f_assertion_valid /\
    d.f_user_verified /\ d.f_assertion_credential_matches /\
    (not d.f_credential_update_needed || d.f_credential_updated) /\
    d.f_account_present /\ d.f_account_epoch_active /\ d.f_share_present /\
    d.f_stored_credential_matches /\
    observed_recovery_epoch d.f_stored_epoch >=. v_INITIAL_EPOCH) /\
  (d.f_grant_stored ==> (d.f_grant_issued /\ d.f_share_decoded /\ is_af_done d))
```

Reachability witnesses exercise the success path, the metadata-update path, the
budget refusal, missing/corrupt/binding-mismatched/replaced challenges, invalid
/ unverified / mismatched assertions, a failed metadata update, freezing,
credential replacement, a missing share, share corruption and grant-store
failure. All are proved from the extracted `begin_*`; none is an assumption.

## Concurrent composition

Module:
[`proofs/fstar/webauthn-driver-composition`](extractions/Vela_recovery_policy_webauthn_driver_composition.fst).

The world is `{ attempt_state : bool; budget : nat; grants : nat;
w_forbidden_release : nat; reqs : list driver }`. A schedule is an arbitrary
list of actions: spawn a request, count an attempt, observe the pre-consumption
context, consume the challenge, deliver the assertion / credential-update /
live-account / share-decode / grant-store observation to any request.

| Real effect | Model |
|---|---|
| sled rate limiter | `Count` spends one unit of a shared budget and is the only way to reach `Consume`; a refused request is delivered `Limited` and must not mark its attempt counted |
| atomic `Store::get_del` | `Consume` sees the challenge iff `attempt_state` and clears it in the same step |
| `users` row / credential comparison / WebAuthn verification / share decode | the schedule chooses the observation delivered in the same step |
| single-use grant store + Share 2 release | one `ReleaseGrant` effect converts the held challenge token into one grant; `Store` records the grant-store success |

Invariant:

```
all_sound reqs
/\ w_forbidden_release = 0
/\ b2n attempt_state + grants + held reqs <= 1
/\ budget + counted reqs <= k
```

Headline theorem:

```
one_challenge_at_most_one_grant (k) (schedule):
  let w = run_world (initial k) schedule in
  w.grants <= 1 /\ counted w.reqs <= k /\ w.budget <= k /\
  w.w_forbidden_release = 0
```

Counters and where they are incremented:

- `grants` — at the driver's `ReleaseGrant` effect, never at a modelled store
  write. `step_tokens` proves a step cannot create a held token or a grant
  except from a fully matched `Present` consumption; `step_tokens_other`
  carries that through non-consumption events.
- `w_forbidden_release` — at the driver's `ReleaseGrant` effect when the
  live-account observation fails `release_facts` (freezing/rotation, a replaced
  stored credential, a missing share, or an incomplete
  challenge/assertion/update chain). `release_requires_observation_facts` proves
  the good driver never increments it.
- `counted` — the sum of the drivers' own `budget_counted` flags;
  `deliver_admit_inv` proves one admitted count spends exactly one budget unit,
  and a refused count leaves the flag false.

Non-vacuity witnesses, checked one world step at a time with `run_cons`: one
grant is reachable; two racing requests issue exactly one grant; with budget 1
the second request is refused; freezing, credential replacement and an
unverified assertion issue no grant.

Assumptions (not proved here): `get_del`/`set_ex`/`set_ex_nx` linearizability,
the rate-limit window implementation, SQL row/guard semantics, the WebAuthn
signature/attestation verification itself, the JSON/base64 decodes, store
TTL/expiry, UUID generation, the handler performing exactly the effect the
driver returns in the same step as its observation, and the challenge having
been created once by an admitted initiation. Initiation and redemption are not
composed in one world.

## Mutation check

Each mutation is applied to a temporary copy of the extracted driver (never
committed); the diff is in `mutation-*.diff` and the failure in
`mutation-*.log`. All three mutated modules still satisfy the extracted
driver's own soundness contracts; the composition theorem is what fails.

| Mutation | Behavioural bug | F* failure |
|---|---|---|
| `mutation-budget` | `AttemptBudgetObservation::Limited` is treated as admitted and advances the driver to `Context` with `budget_counted = true` | headline `one_challenge_at_most_one_grant`: `Assertion failed` (the budget/counted bound is violated) |
| `mutation-retry` | a successful grant store returns the request to `Account` with the grant/ share flags cleared (a retryable grant store) | `step_tokens`: could not prove the token bound; the request holds a challenge token while a grant is already counted, so a second grant becomes reachable |
| `mutation-live-guard` | the live-account facts and credential comparison drop `stored_credential_matches` and force `account_epoch_active` true | `release_requires_observation_facts`: a `ReleaseGrant` is authorized for an observation that does not satisfy the policy, incrementing `w_forbidden_release` |

This shows each counter is load-bearing: the theorem is not true by
construction, and it fails exactly where the mutated driver authorizes the
forbidden effect.

## Tests vs proof

- `cargo-test-recovery-policy.log`: 7 crate unit tests, 8 fact-construction
  tests, 17 possession-driver tests, 12 redemption-driver tests and 23 new
  WebAuthn-driver tests (stage × event coverage, out-of-order inertness, BFS
  reachable-state invariants, one release per request, no release without a
  verified current-credential assertion, only the release effect is
  share-carrying, initiation/registration precedence, lost races and store
  failures).
- `cargo-test-recovery-lifecycle-model.log`: the bounded M14 lifecycle model.
- `cargo-test-recovery-possession-model.log`: the bounded possession handler /
  database trace model (depth 4).
- `cargo-test-server-integration.log`: the full HTTP integration suite after the
  handler rewiring (68 tests).
- `fstar-full-verify.log`: one `./verify-fstar.sh` run — the historical
  90-contract extraction, the enrollment-redemption driver gate, the
  possession-driver gate and this WebAuthn-driver gate all pass.
- `fstar-webauthn-driver.log`: the WebAuthn section of that run (27 contracts,
  four modules, all VCs discharged).

The WebAuthn handler path is not driven by the bounded HTTP models because it
requires genuine authenticator assertions. The driver tests and the F* proof
cover the decision layer; the HTTP status/message mapping is inspected Rust
glue, not proved.

## Bugs found

No production bug was exposed by the refactor. Two proof-engineering defects
were found and fixed while constructing the invariant (they are not handler
bugs):

- an early `update_clean`/`release_clean` formulation reused a stage predicate
  that already required the opposite flag, making the reachability witness
  vacuous; the invariant now states each stage's facts independently;
- the small initiation invariants did not imply `stored ==> authorized`, which
  the trace theorem needs; the conjunct was added (and is preserved by every
  transition).

Two ordering simplifications are deliberate and observable only in impossible or
equivalent cases: the initiation ceremony now starts after the checked policy
and attempt-slot probe (a UUID-v4 collision would previously have started an
unused ceremony), and the live-row absence check now precedes the policy call in
`post_recover` (the policy would reject the same observation). All status codes
and messages are preserved.

## Scope and open obligations

- Scope is one driver instance per request for the per-request module, and one
  shared attempt-bound challenge plus budget for the composition module.
- Depends on the driver (proved): the decision sequence and every authorization
  (which effect is emitted and which facts it requires), for all four requests;
  the unbounded per-request induction; the concurrent counter bounds.
- Modelled, not proved (assumed): `get_del`/`set_ex`/`set_ex_nx` atomicity,
  rate-limit windows, SQL rows and guards, WebAuthn ceremony/signature/
  attestation verification, JSON/base64 decoding, store TTL, UUID generation,
  and the handler performing exactly the returned effect in the same step.
- The observation producers (`observe_recovery_share`,
  `observe_recovery_credential`, `observe_auth_state`, the live-row query, the
  assertion-result mapping, the share decode) and the driver-failure → HTTP
  status/message mapping remain inspected glue.
- The registration-start `set_ex` write is not insert-if-absent; the driver
  records the write outcome but does not claim a single stored state across
  concurrent registration starts (the finish gate consumes whatever state won).
- No hosted CI run is claimed from this worktree; local proof success is not
  hosted CI success.

## Toolchain / commands

- hax 0.3.7, F* 2025.10.06 (`/tmp/vela-fstar-prebuilt/fstar` symlinked to the
  pinned `/home/hirew/.local/opt/vela-formal-fstar-2025.10.06/fstar`), Z3 4.13.3.
- Focused extraction and argv: `verify-fstar-webauthn-driver.sh`; full argv in
  `fstar-webauthn-driver.log`.
- All heavy commands used `~/.local/opt/vela-tools/bin/vela-heavy` (3 GiB, no
  swap, one worker). No uncapped cargo/F* command was run.
- `python3 security/assurance/check-proof-boundary.py` reports **249** selected
  postconditions and zero reviewed `assume val` declarations (14 artifacts).
  The check reads a generated `vela-rekey-policy` extraction that is not
  committed; it was regenerated in this worktree from that crate's own
  `verify-fstar.sh` selection and is not part of this change.
- `python3 -m unittest discover -s security/formal/tests -p 'test_*.py'`
  passes (50 tests), including the auto-discovered
  `extraction-webauthn-driver` source-policy case and the executable-bit check
  for the new runner.
- Hashes: `source-hashes.txt`.

## Hosted reproduction

The [a79cba7 security workflow](https://github.com/lucannez64/VELA/actions/runs/40366675615) verified the WebAuthn extraction,
per-request lemmas and composition with the other recovery gates, and ran the
23 driver tests; all fifteen PR checks passed. `hosted-a79cba7.log` holds the
summary and hashes, which match `source-hashes.txt`.

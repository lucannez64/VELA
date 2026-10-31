# Recovery redemption driver (F-2 increment)

Date: 2026-10-24
Parent: `fdee2bc` (`Exercise iOS decode failure after successful chunk admission`)
Worktree: `/home/hirew/.t3/worktrees/VELA/t3-66a444da`
Heavy-command wrapper: `~/.local/opt/vela-tools/bin/vela-heavy`
Target dir: `/home/hirew/.t3/worktrees/VELA/t3-700776df/target`

This increment owns only:

- `serverVELA/vela-recovery-policy` (new `src/driver.rs`, tests, focused
  extraction and F* gate)
- `serverVELA/vela-server/src/recovery/enroll_device.rs`
- this evidence directory

No global assurance file, manifest, correspondence table or CI file is edited.

## What changed

The handler's entire post-preflight flow now goes through the pure
`vela_recovery_policy::driver` state machine:

1. `begin_redemption(ReadyToConsume)` requests the atomic consumption.
2. `on_grant_consumed` classifies missing / matched / replaced consumption.
3. `on_final_policy_observed` calls the real `enrollment_facts` +
   `plan_enrollment`, combines it with the observed
   `plan_active_mutation` decision, and issues or refuses the insert permit.
4. `on_insert_completed` classifies inserted / zero / errored.
5. `on_authority_rechecked` maps the live recheck to restore-vs-terminal.

The handler performs the effects (`get_del`, SQL insert, live query, restore)
and renders the driver's failure category to the historical HTTP status and
message. Grant semantics are unchanged: possession grants still use commitment
presence (not a digest/generation), WebAuthn grants still use the credential id,
and the legacy epoch fallback is untouched.

## Rust postconditions (checked by hax/F*)

The focused gate selects six functions:

| Function | `requires` / `ensures` |
|---|---|
| `begin_redemption` | effect `Consume`; state sound; stage `Consume`; all authority/success/restore flags false. |
| `step` | requires sound input state; ensures `redemption_effect_is_sound(result.driver, result.effect)` and preserves soundness (`sound input ==> sound result`). |
| `on_grant_consumed` | same postcondition through `step`. |
| `on_final_policy_observed` | same postcondition through `step`. |
| `on_insert_completed` | same postcondition through `step`. |
| `on_authority_rechecked` | same postcondition through `step`. |

`redemption_effect_is_sound` is a Rust predicate over the *resulting* driver:

- `Insert permit` requires stage `Insert`, `consumed_matched`, `permit_issued`,
  `insert_attempted`, no success/restoration, and `permit.epoch/possession`
  equal to the driver's preflight permit.
- `Complete` requires stage `Done`, `insert_succeeded`, and no restoration.
- `RestoreAndFail` requires stage `Done`, `restored`, and **no** success.
- `Fail` requires stage `Done` and no success.
- `FinalPolicy` requires stage `FinalPolicy`, `consumed_matched`, no permit yet.

`redemption_state_is_sound` additionally states: an insert attempt implies a
matched consumption plus both permits; success implies it was attempted, is
terminal (`Done`), and was never restored; restoration implies terminal and no
success.

These are *conditional on the input state being sound*. That is a genuine
inductive invariant, not a hypothesis equal to the desired conclusion: the
hand-written F* module proves it independently and unconditionally for every
trace starting at `begin_redemption`.

## Hand-written F* lemmas (over the actual extracted driver)

Module:
`serverVELA/vela-recovery-policy/proofs/fstar/driver-lemmas/Vela_recovery_policy_driver_lemmas.fst`

It imports the extracted `Vela_recovery_policy.Driver.step` and does not
reimplement the transition machine. It defines its own `trace_sound` predicate,
proves it equal to the extracted Rust predicate, then proves by induction over
arbitrary `list t_RedemptionEvent`:

1. `trace_sound_matches_rust` — independent invariant equals the Rust one.
2. `begin_sound` — the initial driver is sound.
3. `step_sound` — every extracted step preserves soundness.
4. `step_after_success` — a successful driver is inert; no restore follows.
5. `insert_effect_requires_authority` — an `Insert` effect carries matched
   consumption + both permits + exact epoch/type.
6. `consumed_flag_origin` — the matched flag is set only by a matching decoded
   `Present` observation at the preflight epoch/type.
7. `permit_flag_origin` — the permit flag is set only by a `FinalPolicy` event
   whose actual `plan_enrollment` returned `Enroll` at the driver epoch and
   whose actual rekey observation permitted the same epoch.
8. `complete_only_after_inserted` — `Complete` is only a response to
   `InsertObservation::Inserted` from the `Insert` stage.
9. `no_restore_after_success` — step-level no-restore-after-success.
10. `no_restore_after_success_suffix` — any unbounded suffix after success is
    inert and contains zero successes.
11. `complete_count_le_one` — at most one success per driver instance for any
    event list.
12. `no_second_success_after_prefix` — all-pairs corollary: after any
    successful prefix, every unbounded suffix has no further success and no
    restoration.
13. `redemption_trace_theorem` — final soundness, success implies no restore,
    restore implies no success, and success count ≤ 1.
14. `step_after_done` — a finished driver is inert for every event.
15. `done_suffix_inert` — every unbounded suffix after `Done` is inert and has
    zero successes.
16. `insert_stage_never_restores` — no insert outcome emits a restoration;
    the recheck stage (the only later restore source) is reached only by
    `Skipped`.
17. `failed_insert_is_final` — `Failed` yields `Fail(InsertStorage)`, no
    restore, and every later suffix is inert.
18-23. Reachability witnesses: success, terminal insert error, terminal
    credential revocation, policy denial, retryable rotation restoration, and a
    possession-permit insert that has not yet succeeded.

`Complete`, `Fail` etc. are observed effects/decisions. The proof does **not**
claim that SQL/store operations have their intended effects, nor that a
`RestoreAndFail` restoration succeeded. `InsertObservation::Failed` may hide a
committed INSERT, which is why it is terminal.

## Tests vs proof

`cargo-test-recovery-policy.log` covers 7 unit tests, 8 existing fact tests and
12 new exhaustive driver tests (stage × event coverage, out-of-order inertness,
BFS reachable-state invariant checks, one-success-per-instance, no restore after
success, missing/replaced/matched consumption, policy/rekey denial, insert
zero/error/success, every recheck outcome, and the terminal insert error
with an inert suffix).

`cargo-test-server-integration.log` is the full 64-test HTTP integration suite
after the handler rewiring; it includes the existing enrollment grant
redemption, concurrent single-redemption race, preflight ordering, rotation,
credential replacement and possession enrollment tests.

`cargo-test-recovery-possession-model.log` is the bounded possession-recovery
handler/database trace model (depth 4, 60s).

`fstar-full-verify.log` is one `./verify-fstar.sh` run: historical 90-contract
extraction/F* check followed by the focused driver gate. Tests and proof are
separate evidence; neither substitutes for the other.

## Restore/ambiguity issue: found and fixed

Atomic `Store::get_del` (`Tree::remove` linearization) prevents two ordinary
concurrent requests from both consuming one live grant. The first version of
this driver, however, restored the grant after any insert error, and
`insert_recovered_device` can return an error after the `INSERT ... WHERE
EXISTS` committed (lost response). That gave a duplicate path:

1. Request A consumes grant G.
2. A's guarded INSERT commits device D1, but the call surfaces an error.
3. The handler restored G and returned 500.
4. Request B consumes the restored G and the INSERT commits device D2.

One single-use grant could therefore yield two device rows. The fix makes
`InsertObservation::Failed` terminal (`Fail(InsertStorage)`, still rendered as
500 with the database error): the grant stays consumed and the user restarts
recovery. Restoration now only follows paths where nothing was inserted.
Lemmas 16-17 and the test `insert_error_is_terminal_and_never_restores_the_grant`
check the decision; that the handler performs no restore on that branch is
inspected code, and the SQL ambiguity itself is not tested.

## Hosted reproduction

The [aaf708f security workflow](https://github.com/lucannez64/VELA/actions/runs/40122568372) ran `verify-fstar.sh` (90 historical
contracts plus this driver gate) and the 12 driver tests; all fifteen PR checks
passed. `hosted-aaf708f-driver.log` is the job's driver summary: its extraction
and lemma hashes equal the local ones in `source-hashes.txt`.

## Scope and open obligations

- Scope is one request/driver instance. The theorem does not compose concurrent
  requests, does not prove `get_del` atomicity, SQL row/guard semantics, the
  live recheck query, store TTL/restore success, or crash/retry behavior.
- The preflight kernel is unchanged and remains a separate checked decision.
- `InsertObservation::Failed` is an observation; it is treated as possibly
  committed and is terminal.
- Restoration remains unconditional `set_ex` on the no-insert paths; no
  permanent-revocation or exact commitment binding claim.
- No full F-2 closure is claimed. Handler effect traces and concurrent
  single-grant composition remain open.
- The historical 90-contract extraction is byte-identical after the focused
  gate (`git status` on `proofs/fstar/extraction/` is clean).

## Toolchain / commands

- hax 0.3.7, F* 2025.10.06, Z3 4.13.3.
- Full F* argv and source hashes: see `fstar-full-verify.log` and
  `source-hashes.txt`.
- Focused extraction command is in `verify-fstar-driver.sh`; the main
  `verify-fstar.sh` invokes it after the historical check.

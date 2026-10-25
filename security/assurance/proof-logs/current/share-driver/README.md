# Sharing driver (M19/M21 F-2 increment)

Date: 2026-10-25
Target: `serverVELA/vela-server/src/share/mod.rs`
Heavy-command wrapper: `~/.local/opt/vela-tools/bin/vela-heavy`
Target dir: `/home/hirew/.t3/worktrees/VELA/t3-700776df/target`

This increment owns only:

- `serverVELA/vela-share-policy` (new `src/driver.rs`, `tests/driver.rs`,
  focused extraction and F* gate)
- `serverVELA/vela-server/src/share/mod.rs` (handler rewiring only)
- this evidence directory

No global assurance file, manifest, correspondence table, `security/assurance/*.md`
or `security/formal/*` file is edited.

## What changed

Every post-validation decision in the sharing handlers now goes through the
pure `vela_share_policy::driver` state machine:

1. `begin_send` owns the historical admission order: recipient has a signalled
   sharing key, base64 decoding, global capsule cap, inbox item cap,
   per-(sender, recipient) byte cap, recipient total byte cap (via the real
   `send_facts`) and the real `plan_send` authorization.
2. `begin_link_update` / `begin_link_revoke` own the request-side decode/length
   checks and ask the handler to observe the linked row; `on_link_observation`
   calls the real `link_mutation_facts` / `plan_link_mutation`.
3. `begin_inbox_delete` constructs the recipient-scoped delete permit; the
   handler only executes `DELETE ... WHERE id = ? AND recipient_user_id = ?`.
4. `begin_ek_registration` owns the share-EK decode/size and `signed_at`
   canonicalization/parse/skew order before the device row is read;
   `on_ek_observation` calls the real `ek_registration_facts` /
   `plan_ek_registration` and reproduces the handler's historical rejection
   precedence for the stored identity key and signature decode errors.
5. `on_send_completed`, `on_rows_observed` and `on_cleanup_completed` classify
   the transaction/UPDATE/DELETE row observations.

The handlers still perform the effects and render the driver's failure category
with the existing status and message. The SQL statements and their guards are
unchanged. Rust and handler behaviour is unchanged except that an oversized
send now opens the read transaction before the (already-decided) size failure;
the externally visible status/message is identical.

## Rust postconditions (checked by hax/F*)

The focused gate selects eleven functions:

| Function | `requires` / `ensures` |
|---|---|
| `begin_send` | state sound; effect sound; stage `SendInsert` or `Fail`. |
| `begin_link_update` | state sound; effect sound; stage `LinkUpdateObserve` or `Fail`. |
| `begin_link_revoke` | state sound; effect sound; stage `LinkRevokeObserve` with `ObserveLink`. |
| `begin_inbox_delete` | state sound; effect sound; `DeleteInboxItem` with `recipient_scoped`. |
| `begin_ek_registration` | state sound; effect sound; stage `EkObserve` or `Fail`. |
| `step` | requires sound input; ensures effect sound and preserves soundness. |
| `on_link_observation` / `on_ek_observation` / `on_send_completed` / `on_rows_observed` / `on_cleanup_completed` | same postcondition through `step`. |

`share_state_is_sound` ties every non-terminal stage to its request kind and
records: a send authority needs an authenticated session and an authorizing
plan; a link mutation authority needs a sender-owned, live, non-revoked row; a
committed revoke has its cleanup and cannot precede it; an inbox delete carries
the recipient scope; an EK update was authorized by the real registration plan.
It also states that a revoke-kind commit implies `revoked`, and `revoked`
implies the cleanup was requested.

These are conditional on the input state being sound. The hand-written F*
module proves the invariant independently and unconditionally for every trace
starting at each `begin_*`.

## Hand-written F* lemmas (over the actual extracted driver)

Module:
`serverVELA/vela-share-policy/proofs/fstar/driver-lemmas/Vela_share_policy_driver_lemmas.fst`

It imports the extracted `Vela_share_policy.Driver.step`, restates the
invariant independently (`trace_sound`), proves it equal to
`share_state_is_sound`, then proves by induction over arbitrary
`list t_ShareEvent`:

- `trace_sound_matches_rust` — independent invariant equals the Rust predicate.
- `begin_*_sound` — every constructor produces a sound driver.
- `step_sound` — every extracted step preserves soundness.
- `step_kind` / `run_kind` — the request kind is immutable.
- `step_after_done` / `done_suffix_inert` — a finished request is inert for
  every unbounded suffix.
- `run`, `count_completes`, `last_effect` and their `*_from_*` wrappers.
- `send_effect_requires_authentication_and_plan` — an `InsertCapsule` effect
  implies the authenticated-session observation and the real `plan_send`
  `Deliver` decision, and carries the observed capsule length.
- `send_effect_implies_session_observed` — that authority implies the session
  observation itself.
- `link_effect_requires_plan` — an update/revoke effect implies the real
  `plan_link_mutation` returned `Apply`.
- `link_effect_implies_sender_and_live` — only the sender can mutate/revoke a
  link: the observed row existed, the caller was the sender, and the row was
  not revoked.
- `revoked_link_cannot_mutate` — an observation that saw `revoked` cannot
  produce an update/revoke effect.
- `begin_inbox_delete_is_recipient_scoped` — an inbox delete permit is always
  recipient-scoped.
- `no_commit_and_revoke_after_send` / `..._after_revoke`.
- `complete_count_le_one` — at most one committed success per request instance.
- `revoke_cleanup_reaches_complete`.

Reachability witnesses: send success, unauthenticated send rejection, sender
update success, foreign update rejection, revoked update rejection, revoke
success plus cleanup, recipient inbox delete success, device-signed EK
registration success, and the send permit's exact capsule length.

## Composition theorem

Module:
`serverVELA/vela-share-policy/proofs/fstar/driver-composition/Vela_share_policy_driver_composition.fst`

The world is a shared link state, a pending inbox item, an inbox item count, an
optional item quota, a list of per-request drivers and three counters. A
schedule is an arbitrary list of actions: spawn any request, commit a send,
atomically observe+commit an update or revoke, deliver the revoke cleanup, or
commit an inbox delete / EK registration. A revoke atomically sets
`revoked = 1` and removes the pending inbox row; an update/revoke observation
and its guarded write are one action (the SQL `WHERE sender_user_id = ? AND
revoked = 0` is modelled atomically, like the template's `get_del`); an inbox
delete atomically checks `recipient_user_id = ?`; a send commit rechecks the
item quota.

Proved:

- `share_composition_theorem`: for every schedule, the shared invariant holds,
  the inbox count never exceeds a configured quota, and
  `w_non_sender_changes = 0`: the driver never authorized an update or revoke
  for a non-sender.
- `revocation_is_final`: after any prefix that leaves the link revoked, every
  unbounded suffix keeps it revoked and commits no update
  (`w_update_commits` is unchanged).
- `inbox_delete_only_by_recipient`: an inbox delete can only lower the count
  when the acting request is the recipient.
- `only_sender_changes_link`: the non-sender change counter is zero on every
  schedule.
- `world_step_inv`: every action preserves the invariant.
- Witnesses, checked world-step by world-step with `run_cons`: a send fills the
  quota exactly; a send at the quota is refused; a sender update commits; a
  third party update is refused; a revoke is followed by a refused update; a
  third-party inbox delete is refused and a recipient delete succeeds; an EK
  registration commits.

### What each result depends on (parent review)

- **Depends on the extracted driver:** revocation finality and
  `w_non_sender_changes = 0`. In the delegated version the non-sender counter
  was never incremented, so that theorem held by construction. The parent
  review changed the world to increment it whenever the driver emits an
  update/revoke effect for a non-sender (even though the modelled SQL guard
  then writes no row), and the proof now uses the per-request lemma
  `link_effect_implies_sender_and_live`.
- **Depends on the modelled SQL/transaction semantics, not on the driver:**
  `inbox_delete_only_by_recipient` (the `recipient_user_id = ?` guard is part
  of the world) and the quota bound (the send commit rechecks the quota
  atomically). The real handler reads the quota and inserts inside one SQL
  transaction; the bound holds if those transactions serialize (SQLite/Turso
  write serialization). The insert itself has no quota predicate.

## Mutation check

`mutation-drop-revoked-guard.log` is the F* output after editing a **copy** of
the extracted driver (never committed): `link_mutation_facts` was changed to
drop `obs.f_item_not_revoked` from `f_not_already_revoked` (ensures and body
kept consistent). The composition then fails at
`revoked_update_observation_rejected` (line 598): a revoked observation would
authorize an update, so the revocation-finality proof no longer goes through.
The mutant lives only in `/tmp/opencode/share-mutant`.

`mutation-drop-sender-check.log` (parent review): in a copy of the extraction,
`link_mutation_facts` sets `f_caller_is_sender = obs.f_item_present` (dropping
the sender comparison; ensures and body kept consistent). Checking fails at
`link_effect_implies_sender_and_live`, which `commit_update_inv` and
`commit_revoke_inv` use, so the sender-only result depends on the driver.

## Tests

- `cargo-test-share-policy.log`: 4 existing unit tests, 13 new exhaustive
  driver tests and 3 existing fact-construction tests pass. The driver tests
  cover every stage × event pair, out-of-order inertness, BFS reachable-state
  soundness and effect-authority checks, the send quota/precedence order, the
  link sender/live/revoked gate, update vs revoke, revoke cleanup, send/EK
  results, EK error precedence, inbox-delete scope and terminal inertness.
- `cargo-test-share-channel-model.log`: the bounded M19b/M21 handler/database
  conformance model (depth 3) still passes unchanged.
- `cargo-test-server-integration.log`: the full 65-test HTTP integration suite
  passes, including `share_ek_registration_requires_device_signed_binding`,
  share send/poll and the recovery/rekey/device suites.
- `fstar-full-verify.log`: one `./verify-fstar.sh` run — historical 23-contract
  extraction/F* check, focused driver gate, per-request lemmas and composition.
  All verification conditions discharged; no `admit`, `assume` or `--lax`.
- `python3 security/assurance/check-proof-boundary.py` reports 14 artifacts,
  249 selected postconditions and 0 unreviewed `assume val`. The historical
  `proofs/fstar/extraction/Vela_share_policy.fst` is byte-identical
  (`git diff` is empty).

## Bugs found

No security bug was found and no handler behaviour was changed. In
particular, the existing SQL guards already recheck sender ownership and
`revoked = 0` at update time, and the inbox delete is recipient-scoped; the
driver reproduces those decisions rather than weakening them.

One assumption is worth recording: the composition models the send quota check
and the two inserts as one atomic commit. The real handler reads the quota
inside a transaction and then inserts; the SQL insert itself has no quota
predicate. SQLite/Turso write serialization is what prevents an over-quota
commit under racing sends. Proving that serialization (or adding a conditional
insert) is an open obligation, not a claimed result here.

## Hosted reproduction

The [e89ebed security workflow](https://github.com/lucannez64/VELA/actions/runs/40147963623) ran the driver gate; all fifteen PR
checks passed. `hosted-e89ebed.log` is its summary; the hashes match
`source-hashes.txt`.

## Scope and open obligations

- Scope is the sharing handlers only. SQL statement semantics, transaction
  isolation, row-read origins, UUID uniqueness and crash/retry are not proved.
- The driver's row observations are trusted inputs produced by the handler; the
  composition models the guard-read and guarded write as one atomic action.
- The send quota atomicity assumption above is not discharged.
- The per-request proofs do not claim that the handler performs the effect
  exactly as instructed; that remains inspected code plus the bounded
  conformance model.
- The historical 23-contract extraction is byte-identical after the focused
  gate.
- No global correspondence/assurance manifest is edited; the parent integrates
  this evidence.

## Toolchain

- hax 0.3.7, F* 2025.10.06, Z3 4.13.3.
- Full F* argv and source hashes: `fstar-full-verify.log`,
  `source-hashes.txt`, `commands.txt`.

# Concurrent web-session composition

## Claim

`serverVELA/vela-session-policy/proofs/fstar/websession-composition/Vela_session_policy_websession_composition.fst`
composes the **extracted** start, grant, token and delete drivers
(`Vela_session_policy.Websession_driver`) with the **extracted** device
revocation driver (`Vela_session_policy.Revocation_driver`, U-18 cascade) over
one shared world:

- `web_sessions` rows (`pending`/`granted`/`revoked`, owner account, approver
  account/device, mode, epoch);
- the `web_token` challenge store (atomic `take`, wrong purpose spends);
- the per-session first-writer-wins claim `web_session:token_issued:<id>`
  (atomic `set_ex_nx`);
- the `device:revoked:<session_id>` lockout sentinel, SQL row revocation and
  the approved-session cascade;
- devices and accounts, and the issued tokens.

A schedule is any finite interleaving of actions. Each request owns its own
extracted driver value; every observation about shared state is computed from
the live world at the step the handler reads it; the effect is applied in that
same step. The claim action performs the atomic `set_ex_nx` and feeds the
resulting `Claimed`/`AlreadyClaimed`; the challenge action performs the atomic
take.

## Exact theorem

```fstar
let composition_theorem (schedule : list action) : Lemma (
  let w = run_world initial schedule in
  inv w /\
  all_sessions_ok w.w_sessions /\
  w.w_token_after_delete = 0 /\
  w.w_token_after_approver = 0 /\
  w.w_cross_account_grant = 0 /\
  w.w_inactive_grant = 0 /\
  w.w_nonpending_grant = 0 /\
  w.w_token_from_pending = 0 /\
  w.w_cross_account_delete = 0 /\
  w.w_start_authority = 0)
```

`inv w` is `all_sessions_ok w.w_sessions /\ all_reqs_ok w.w_reqs /\
counters_ok w`. `all_sessions_ok` says every row has `s_issue_decisions <= 1`,
a session with an `IssueToken` decision has the claim key set, a delete lockout
or cascade implies the sentinel, a revoked row has the sentinel, and a pending
row has no owner/approver device. The five named consequences are also exposed
as separate lemmas (`no_double_token`, `no_token_after_revocation`,
`grants_only_from_the_owner`, `start_creates_no_authority`,
`no_cross_account_delete`).

1. **At most one token per session.** `w_sessions[*].s_issue_decisions <= 1`,
   incremented only on the extracted token driver's `IssueToken` effect, never
   on the claim store. The claim key can be won once; `AlreadyClaimed` is a
   terminal refusal in the driver.
2. **No token after revocation.** `w_token_after_delete = 0` and
   `w_token_after_approver = 0`; the issue effect is guarded by the live
   `device:revoked:<session_id>` sentinel, which both the delete lockout and
   the U-18 cascade write before the SQL row flips.
3. **Grants only from the owning active approver, only pending.** The
   `UpdateGrant` decision is counted against the live observation
   (`w_cross_account_grant`, `w_nonpending_grant`), and the modelled CAS
   commits only for a pending row, an active account at the permit epoch, and
   an active device owned by the actor (`w_inactive_grant`). The SQL's
   redundant `approver_user_id` re-check is deliberately **not** modelled; the
   extracted checked grant plan supplies the approver binding, so the model is
   stronger than the shipped CAS.
4. **Start creates no authority.** `w_start_authority = 0`; a start insert adds
   only a `pending` row with no owner/approver device and zero issue decisions,
   and `w_token_from_pending = 0` says no token is authorized from a
   non-granted observation.
5. **No cross-account delete.** `w_cross_account_delete = 0`, counted on the
   delete driver's `LockoutSession` decision against the live owner.

## Counters

| Counter | Keyed on | Must be |
|---|---|---|
| `s_issue_decisions` | extracted `IssueToken` effect (not the claim store) | `<= 1` each |
| `w_token_after_delete` | an issued token whose session had the delete lockout/revocation | `0` |
| `w_token_after_approver` | an issued token whose session had the approver cascade | `0` |
| `w_cross_account_grant` | `UpdateGrant` with approver ≠ authenticated account | `0` |
| `w_inactive_grant` | a grant commit with an inactive device/account | `0` |
| `w_nonpending_grant` | `UpdateGrant` on a non-pending observation | `0` |
| `w_token_from_pending` | `IssueToken` from a non-granted observation | `0` |
| `w_cross_account_delete` | `LockoutSession` for a non-owner | `0` |
| `w_start_authority` | a start insert carrying authority | `0` |
| `w_tokens_issued`, `w_grants`, `w_delete_lockouts` | witness aids | — |

## Reachability witnesses

The theorem is not vacuous; all witnesses are checked in the module:

- `one_token_is_reachable` — a granted session with a `web_token` challenge
  runs the full exchange and ends with `w_tokens_issued = 1`,
  `length w_tokens = 1`, `s_issue_decisions = 1`, `s_claimed = true`.
- `second_token_attempt_is_refused` — a second fresh challenge/proof reaches
  `AlreadyClaimed`; the driver is `Done`/failed and the world still has exactly
  one token and one issue decision.
- `token_after_delete_is_refused` — delete reaches sentinel + SQL revocation
  (`s_phase = Revoked`, `s_sentinel = true`, `s_revoked_by_delete = true`),
  then a token request fails at its session observation (`f_failed = true`,
  `f_session_loaded = false`) and `w_tokens_issued = 0`.
- `start_creates_a_pending_row_only` — start appends a second `pending` row
  with no owner/approver device and `w_start_authority = 0`.

## Assumptions

Proved nowhere in this module:

- SQL statements and the guarded grant/delete updates are linearizable and
  atomic; sled `get_del` (challenge take) and `set_ex_nx` (claim) are atomic.
- The handler performs exactly the effect the driver returns, in the same step
  as its observation; each executor reports its storage outcome honestly.
- The token **issue** effect re-checks the `device:revoked:<session_id>`
  sentinel before releasing a token. This was a real in-flight gap (a request
  that observed a granted row before a delete/cascade could release a token
  after the lockout); it is fixed in
  `serverVELA/vela-server/src/web_session/mod.rs` (`issue_token`) and covered
  by `web_session_token_is_not_issued_after_its_lockout`.
- The approver-revocation commit for a web session is its cascade (sentinel +
  row revocation), which follows the device row update in the same revocation
  request. An exchange linearized between the device row update and the cascade
  is ordered before the session's revocation; its token is still bounded by
  the sentinel at use.
- Hybrid signature verification, PASETO signing, the clock, TTLs, rate limits
  and multi-node visibility are trusted/outside. Devices are not transferred
  between accounts. Account deletion and its web-session lockout are outside
  this module (the deletion composition covers them).

## Mutations

Each mutation is applied to a **copy** of the extracted modules under
`/tmp/vela-wsc-mut/`; the committed extraction is never modified. Every run
invokes F* over the same composition module and fails:

| Mutation | Check removed | Result |
|---|---|---|
| `mutation-token-claim` | `AlreadyClaimed` becomes an `IssueToken` decision | driver step/effect soundness fails (proof rejected) |
| `mutation-token-session` | granted-phase check in `on_token_session` | `token_eligible_granted` / property 4 fails |
| `mutation-delete-owner` | owner equality in `on_delete_session` | `delete_lockout_owner` / cross-account counter fails |
| `mutation-grant-approver` | `facts.f_approver_matches` in `grant_is_authorized` | `grant_update_observation` / property 3 fails |
| `mutation-delete-sentinel` | `StorageFailed` treated as `Applied` | `delete_sentinel_step` / lockout-before-record invariant fails |

Diffs are `mutation-*.diff`; F* logs (with the failing line) are
`mutation-*.log`.

## Gates

```bash
cd serverVELA/vela-session-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh websession
~/.local/opt/vela-tools/bin/vela-heavy cargo test --manifest-path ../Cargo.toml -p vela-session-policy
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
python3 security/assurance/check-proof-boundary.py
python3 security/formal/check-correspondence.py
```

`gate.log` is the standalone
`./verify-fstar-websession-composition.sh` run. The source guard,
`test_driver_proof_sources.py` and the correspondence check are also green in
the final report.

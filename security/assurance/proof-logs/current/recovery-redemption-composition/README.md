# Concurrent enrollment-redemption composition (F*)

`serverVELA/vela-recovery-policy/proofs/fstar/driver-composition/Vela_recovery_policy_driver_composition.fst`
composes the extracted `Vela_recovery_policy.Driver.step` across any number of
concurrent requests sharing one enrollment grant.

## Model

A schedule is an arbitrary list of actions: start a request, expire the grant,
or deliver the next observation to any request. The world abstracts the
handler's effects:

| Real effect | Model |
|---|---|
| `Store::get_del` of the grant | atomic: `Present` iff the grant is still stored, removed in the same step |
| guarded device `INSERT` | `Inserted` writes a row, `Skipped` writes none, `Failed` may or may not have written one (the schedule chooses) |
| `restore_enroll_grant` | re-arms the grant exactly when the driver returns `RestoreAndFail` |
| grant TTL | `Expire` removes the grant at any time |

Final-policy and recheck observations are arbitrary.

## Results

- `one_grant_at_most_one_device`: for every schedule, at most one device row
  is written for the grant. Proof: the store copy, rows written, and grants
  held by in-flight requests sum to at most one, and every extracted step
  preserves that (`step_tokens`, `insert_tokens`, `world_step_inv`).
- Witnesses, checked step by step: a single success writes one row; two racing
  requests write one row (the loser sees the grant missing); a definite
  zero-row insert during rotation restores the grant and a later request then
  succeeds; an errored insert that committed leaves the grant consumed and a
  later request fails.
- Mutation check (`mutation-restore-after-error.log`): restoring the extracted
  driver's pre-`aaf708f` behavior (restore after an insert error) makes the proof
  fail at `insert_tokens`, so the theorem depends on that fix.

`fstar-full-verify.log` is one `verify-fstar.sh` run: the historical
90-contract check, the per-request driver gate and this module. No `admit`,
`assume` or `--lax` is used.

## Assumptions and open obligations

- `get_del` is linearizable and the handler performs exactly the effect the
  driver returns, with each observation delivered together with its effect.
- The grant key is issued once (random id); grant issuance, the SQL guard's
  meaning and observation origins are not modeled.
- Store or database calls that fail outright are modeled only through the
  driver's observations; crash recovery is out of scope.
- This is one grant. Device rows for distinct grants, and enrollment through
  paths other than this handler, are not covered.

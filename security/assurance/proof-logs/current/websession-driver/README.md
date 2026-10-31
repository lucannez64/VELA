# Web-session decision drivers: start, grant, token exchange, delete

## Claim

The four state-transition handlers in
`serverVELA/vela-server/src/web_session/mod.rs` reach their decisions through
the pure drivers in `serverVELA/vela-session-policy/src/websession_driver.rs`.
The checked per-request facts are:

- `post_start` can emit only `InsertPending`, and only after the IP limiter and
  validation; it has no grant, token or revoke effect, so a start creates only a
  `pending` row with no authority.
- `post_grant` emits `UpdateGrant` only from a state where the extracted
  `plan_observed_grant` returned a permit for an authenticated, active device,
  a pending session, a matching approver and 32-byte nonce, and (for RW) a
  registered web key. The effect carries the permit's mode/epoch and the
  `clamp_web_ttl` value. A response requires the CAS to report `Updated`.
- `post_token` emits `IssueToken` only after the `web_token` challenge take
  reported `Accepted` (the take is atomic and purpose-bound), the verifier
  reported valid, and a first-writer-wins claim succeeded. The plan is the one
  returned by `plan_observed_web_token`; each request emits at most one issue
  effect.
- `delete_session` emits `LockoutSession` and `RecordRevocation` only for the
  authenticated account that owns (granted) or is committed to (pending) the
  session, and the SQL record follows the sentinel.

The trace module `proofs/fstar/websession-driver-lemmas` proves, for every
event list: soundness, at most one success/failure and at most one token issue,
and that each emitted effect satisfies the invariant that produced it. The
drivers call the verified policy (`plan_observed_grant`,
`plan_observed_web_token`, `clamp_web_ttl`) instead of re-deciding.

## What changed in the handlers

The handlers now expand one interpreter macro each with `await`. Statuses,
messages, SQL text, store keys and effect order are otherwise unchanged. The
one behavioural hardening is the token claim:

- `POST /web-session/:id/token` writes
  `web_session:token_issued:<session_id>` with `set_ex_nx` before signing. A
  second valid proof (with a fresh `web_token` challenge) therefore returns
  `409 Conflict` instead of minting a second token for the same grant.
- Regression test:
  `web_session_issues_at_most_one_token_per_grant` in
  `serverVELA/vela-server/tests/integration.rs`, and the bounded challenge
  model now knows the per-session claim.

## Mutations

Mutations are applied to copies under `/tmp/vela-f2-websession-mut/`; the
committed extraction is untouched. Each mutation makes F* fail:

| Mutation | Result |
|---|---|
| `mutation-start.diff`: `StartEffect::InsertPending` becomes `StartEffect::CheckRateLimit` | driver lemma/effect-soundness fails |
| `mutation-grant.diff`: `UpdateGrant` is emitted without `plan_authorized` | `grant_step_effect_sound` / trace theorem fails |
| `mutation-token.diff`: `IssueToken` is emitted before the claim | token effect-soundness / at-most-one issue fails |
| `mutation-delete.diff`: `RecordRevocation` is emitted for a non-owner | `delete_step_effect_sound` / owner theorem fails |

Logs are in this directory (`mutation-*.log`, `gate.log`).

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly. SQL linearizability, sled `get_del`/`set_ex_nx` atomicity,
  hybrid verification, PASETO signing and the clock are outside the model.
- The grant driver observes the middleware's active-device fact and the SQL CAS
  re-checks `revoked = 0`; the driver does not itself observe the database.
- The token driver treats `clave consumed` and `signature valid` as
  observations; the handler computes them from the real take and verifier.
- Concurrent composition over the shared session/challenge store, including the
  revocation cascade, is **not** included in this increment. The per-request
  and interpreter proofs are complete; composition remains open.

## Reproduction

```bash
cd serverVELA/vela-session-policy
./verify-fstar-websession-driver.sh
./verify-fstar-websession-interpreter.sh
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

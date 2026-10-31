# GET /auth/challenge: issue driver

## Claim

The pure `vela_session_policy::challenge_issue_driver` owns every decision the
challenge handler makes between effects: whether the requested purpose parses,
whether the per-IP limiter allowed the request, whether the OS returned exactly
32 bytes, whether the atomic first-writer-wins store reported the key absent,
and therefore whether exactly one challenge is issued. The extracted `step` is
total; every mismatched or out-of-order event is inert.

`issue_trace_theorem` quantifies over every purpose observation and every event
list:

```fstar
let d = run_from_purpose purpose events in
trace_sound d /\
(d.f_issued ==>
  (d.f_purpose_valid && d.f_rate_allowed && d.f_nonce_valid && d.f_stored_fresh)) /\
(d.f_stored_fresh ==> d.f_purpose_valid) /\
not (d.f_issued && d.f_failed) /\
count_issue ... <= 1 /\ count_fail ... <= 1 /\
count_store ... <= 1 /\ count_nonce ... <= 1 /\
(count_store ... = 1 ==> (begin_issue purpose).f_driver.f_purpose_valid)
```

The store effect requires the parsed purpose, an allowed limiter and a 32-byte
nonce; `Issue` requires a fresh stored key. The stuttering counter lemmas use
the extracted `issue_stage_index` monotonic contract, so one request cannot
store twice. Witnesses cover success, invalid purpose, a denied limiter, a short
nonce, a collision, a storage failure and terminality after issue.

## The one handler change

`get_challenge` used `Store::set_ex`, which silently overwrites an existing
`challenge:<nonce>` value. It now uses `Store::set_ex_nx` and fails closed on a
collision, so a fresh 32-byte nonce never replaces another live challenge. The
store key, TTL, purpose tags, statuses, messages and effect order are otherwise
unchanged. The store's first-writer-wins behaviour already has unit and
concurrency tests in `src/store.rs`.

## Handler wiring

`serverVELA/vela-server/src/auth/challenge.rs` expands
`challenge_issue_interpreter!` exactly once with `await` over
`ChallengeIssueIo`, which holds all of the request's I/O. Parse failure is passed
to the driver as `PurposeObservation::Invalid`; the exact handler error stays in
the executor's `error` slot.

## Mutation

`mutation-1.diff` changes the extracted `on_store` collision branch to issue a
response with `stored_fresh = true` instead of failing. The reachability witness
`collision_is_reachable` fails (`mutation-1.log`). The mutant is a copy under
`/tmp/vela-f2-account-a-mut/`, never committed.

## Assumptions and non-claims

- The limiter, OS random source and sled write are effectful glue; the driver
  sees only their reported observations.
- `Store::set_ex_nx` is atomic and linearizable; the crate has unit and
  eight-thread race tests for it.
- Freshness means this request's atomic write reported the key absent, not that
  two independent requests use different random bytes.
- The hax models and solver remain trusted.

## Reproduction

```bash
cd serverVELA/vela-session-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-challenge-issue-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy cargo test --manifest-path ../Cargo.toml -p vela-server --test challenge_single_use_model
```

`focused-verify.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).

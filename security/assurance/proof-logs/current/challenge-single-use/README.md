# Challenge single-use across every consumer (bounded conformance + concurrency)

Test: `serverVELA/vela-server/tests/challenge_single_use_model.rs` (CI:
`formal-rekey`, step "Check bounded policies and rekey handler/database
conformance", default depth 3).

`GET /auth/challenge` stores a 32-byte nonce as `challenge:<b64>` in sled with a
60-second TTL (`src/auth/challenge.rs:46-47`). Exactly three handlers consume
that namespace with `Store::get_del`:

| Endpoint | Handler | `get_del` line |
|---|---|---|
| `POST /auth/verify` | `src/auth/verify.rs` | 46 |
| `POST /device/enroll` | `src/device/enroll.rs` | 84 |
| `POST /web-session/:id/token` | `src/web_session/mod.rs` | 677 |

The recovery `get_del` calls are a different universe: they consume
attempt-bound keys (`recovery:webauthn:auth:{user}:{id}` in
`recovery/initiate.rs`, `recovery:possess:proof:{user}:{id}` in
`recovery/possess.rs`, `recovery:enroll_grant:{user}:{grant}` in
`recovery/recover.rs`), never a `challenge:` key, so a `/auth/challenge` nonce
cannot be presented there and vice versa. Those keys are covered by
`recovery_possession_model.rs` and the recovery integration tests.

## Reference model

A challenge is a linear token:

- issuing one creates a **fresh** token (the model keeps every issued nonce, not
  just the latest: re-issuing into a slot does not revoke an earlier live nonce);
- presenting it at any endpoint consumes it **before the proof is checked**;
- a consumed, expired or never-issued nonce is refused at every endpoint;
- a nonce yields **at most one success across all three endpoints**.

The server does **not** bind a purpose into `challenge:<b64>`. The model records
the same fact: a nonce is endpoint-agnostic and may be presented at any consumer,
but only once. The test does not pretend a purpose binding exists. Every endpoint
still verifies its own action proof under its own key (`auth_message(device_id,
nonce)` for verify/enroll, the web session's ephemeral key for web-token), so the
exploration found no cross-endpoint privilege escalation — see "Observation"
below.

## Consumption ordering (from the handlers, asserted by the tests)

| Handler | Order |
|---|---|
| `/auth/verify` | rate limits → `get_del` → device lookup → signature |
| `/device/enroll` | rate limit → `get_del` → device lookup → auth signature → payload checks |
| `/web-session/:id/token` | rate limits → session status/mode/expiry → `get_del` → signature → policy |

Therefore an **invalid proof consumes** at all three consumers, while a
web-token request refused by a pre-`get_del` session check does **not** consume.
`failed_or_unknown_or_expired_or_replayed_challenges_never_succeed` pins both
facts directly; the exhaustive model models the valid-session path.

## Exploration

Every command sequence up to `VELA_CHALLENGE_MODEL_DEPTH` (default 3) over a
19-command alphabet (2 slots; issue/expire; valid and invalid presentation at
each of the 3 endpoints; unknown nonce at each endpoint) runs against the model
and the real Axum router with the real Turso schema and sled store. After every
step the test compares the HTTP status **and the presence of every issued
challenge key**. A nonce accepted twice, or a key left behind after a
presentation, fails immediately.

The alphabet issues real nonces obtained from `GET /auth/challenge` before the
exploration. Re-arming a pre-issued nonce with `set_ex` under the same
`challenge:<b64>` key for an independent trace is what makes valid signatures
precomputable; every nonce in the pool came from the real endpoint and the
focused test asserts that endpoint stores it.

| Depth | Traces | Steps | Result |
|---|---:|---:|---|
| 3 (CI default) | 7,240 | 21,318 | pass, 3.07 s (`depth3.log`) |
| 4 (`VELA_CHALLENGE_MODEL_DEPTH=4`, local) | 137,561 | 542,602 | pass, 73.87 s (`depth4.log`) |

All distinguished outcomes are exercised (200 and 401 at each endpoint; 401 for
an unknown nonce at each endpoint; issue and expire; 84/5,712 presentations of a
dead challenge at depth 3/4). Successes per nonce are asserted to stay ≤ 1 after
every step.

## Real concurrency

`one_challenge_yields_exactly_one_success_under_concurrency` issues one real
challenge, then fires 16 simultaneous requests through the real router on a
multi-thread runtime (one Turso connection per request, distinct source address
per request, per-session web-token budget reset per round). 42 rounds: 6
all-verify, 6 all-enroll, 6 all-web-token, and 24 mixed-endpoint rounds
(672 requests total). Every round has **exactly one** `200`; every other request
is `401`. Each consumer wins at least one round; the per-run distribution is
recorded in `depth3.log` (e.g. `{"PresentEnroll": 7, "PresentVerify": 29,
"PresentWebToken": 6}` in the checked-in run).

## The test can fail (mutation check, applied locally and reverted)

Mutation in `src/auth/verify.rs`: `Store::get_del` → `Store::get` (non-consuming).

| Test | Detection |
|---|---|
| focused semantics test | fails at "Verify did not consume the challenge on an invalid proof" (`mutation-get-instead-of-get_del.log`) |
| exhaustive model | fails at `[Issue(0), Present { slot: 0, endpoint: Verify, honest: true }]`: the model says consumed, the store still holds the key (`mutation-model-get-instead-of-get_del.log`) |

`git diff -- serverVELA/vela-server/src/` is empty after the revert. No handler
change was kept.

## Observation: no purpose binding

A nonce issued by `/auth/challenge` is accepted at `/device/enroll` and
`/web-session/:id/token` as well as `/auth/verify`, provided that endpoint's own
proof verifies (the exhaustive traces `[Issue(0), Present(0, Enroll, true)]` and
`[Issue(0), Present(0, WebToken, true)]` succeed). This is not a replay: the
nonce is still consumed by the first success anywhere. It is also not an
escalation found here, because verify/enroll require a device signature over
`auth_message(device_id, nonce)` and enrollment additionally signs the enrollment
payload, while web-token requires the browser's ephemeral key; none of those
proofs is interchangeable.

The symbolic models do not claim a shared purpose binding: M27 is login-only and
M12 models its own `ChallengeIssued` after a grant. If "challenge issued for X
cannot be used for Y" is intended as an assurance claim, the implementation does
not provide it and this test models the absence rather than hiding it. Recorded
as an observation, not a server bug.

## Not covered

Executable evidence for bounded sequential traces plus one concurrency shape,
not a proof.

- Signature-scheme security or key compromise (both hybrid components are assumed
  to authenticate their messages).
- Distributed or multi-node stores: `get_del` relies on sled's single-node
  linearization point. A multi-node store without an atomic take could break the
  property; that topology is not tested.
- Crash/restart between `get_del` and the response: the challenge is consumed
  (safe-fail, retry needs a fresh nonce), but the window is not exercised.
- A real 60-second TTL wait: expiry is simulated by removing the key, which is
  exactly what a read after expiry observes.
- Unknown-device / revoked-device / not-found paths in verify/enroll: the fixture
  uses a live device, so the "consume before lookup" order is inspected but not
  separately driven.
- Rate-limit and quota interactions under sustained load: fresh source addresses
  and a per-round reset of the web-token session budget keep them out of the way.
  (The concurrency test opens Turso with one connection per racing request; the
   one-connection `helpers::test_state` pool otherwise returns 500s from
  concurrent session lookups, which would mask a refusal. This is a test-harness
  detail, not a challenge finding.)
- WebAuthn recovery, which needs genuine authenticator assertions.
- The rest of each endpoint's authorization logic after the challenge (device
  revocation races, token issuance, capsule contents).

## Reproduce

```sh
# CI shape (Docker/heavy wrapper used locally on this machine)
cargo test --manifest-path serverVELA/Cargo.toml --test challenge_single_use_model

# deeper local exploration (~74 s)
VELA_CHALLENGE_MODEL_DEPTH=4 \
  cargo test --manifest-path serverVELA/Cargo.toml \
  --test challenge_single_use_model every_bounded -- --nocapture
```

# Verified web-session capability policy

This crate is the pure production policy for temporary browser capabilities.
Tamarin M12 proves the protocol lifecycle; hax extracts the Rust decisions to
F* and checks their postconditions for every input.

| Production decision | Universally checked property |
|---|---|
| `parse_scope_claim` | Explicit unknown scopes reject; `web_session` cannot parse as `device`. Missing claims retain the bounded legacy-device interpretation. |
| `plan_grant` | A grant requires a pending session, matching approver and nonce, a positive epoch, and an RW verification key when RW is requested. |
| `plan_web_session_token` | Issuance requires a live RW grant, its bindings, one consumed challenge, and a valid signature; the plan is always web-scoped and epoch-bound. |
| `plan_device_token` | Device issuance has device scope, no web epoch, a live expiry, and an overflow-safe hard cap. |
| `plan_renewal` | Renewal preserves the exact scope, optional epoch, and hard cap while bounding the new expiry. |
| `authorize_route` | Web sessions may access vault routes but can never receive a permanent-account route permit. |
| `renewal_escalates_authority` | Renewal never changes scope or epoch. |
| `terminal_session_issues_token` | Revoked and expired sessions never issue tokens. |
| `challenge::classify_stored_tag` | Exact stored-tag bytes are recognized only as `login`, `enroll` or `web_token`; every other length/byte pattern is `Unknown`. |
| `challenge::classify_consumption` | A present tag is accepted only for its own purpose; a present wrong/unknown tag is `WrongPurpose` and the take has already spent it; absence is `Missing`. |
| `login_driver::begin_login` / `step` | `/auth/verify` can respond only after an accepted login challenge, a present unrevoked device, a valid actual verifier result, a successful backoff reset, issuance and JTI tracking; a failure is terminal and never responds. |

The proof boundary excludes PASETO cryptography, HTTP parsing, signature
verification, clocks, SQL execution, and storage atomicity. Production code
turns those observations into policy facts and signs only the private
`TokenPlan` returned by the policy. Handler, state-model, and concurrency tests
cover the boundary to Turso and sled.

## Run

Use the hax 0.3.7, Rust nightly 2025-11-08, F* 2025.10.06, and Z3 4.13.3
toolchain documented in
[`../vela-rekey-policy/README.md`](../vela-rekey-policy/README.md). Then run:

```bash
export PATH="$(opam var bin --switch vela-hax):$(opam var bin --switch vela-fstar):$HOME/.local/bin:$PATH"
./verify-fstar.sh
```

The runner tests the crate, extracts the historical 21 production/theorem
entry points, checks them without `--lax`, and then invokes
`verify-fstar-login-driver.sh` in a separate `cargo hax`/`fstar.exe` invocation.
That focused gate extracts `challenge` and `login_driver` into
`proofs/fstar/extraction-login-driver/` (never mixed with the historical
`proofs/fstar/extraction/` root module) and checks the hand-written raw-byte
challenge refinement and the unbounded login trace lemmas.

Run the protocol model separately:

```bash
cd ../../security/formal
./run-session-proofs.sh
```

Expected: **14 verified, 0 falsified, 0 warnings**.

## Observation construction

`grant_facts` computes the approver comparison from optional account IDs and
requires both a 32-byte nonce and a successful nonce comparison. `web_token_facts`
computes account binding from two present, equal account IDs: `(None, None)`
never grants authority. Both preserve every other supplied observation exactly.
`plan_observed_grant` and `plan_observed_web_token` compose these constructors
with the existing decisions and are called by the production web-session
handlers. Six negative theorems cover absent approvers, wrong nonce length,
cross-account exchange, missing accounts, unconsumed challenges and invalid
signatures. The signature observation comes from the actual verifier result.

The current runner selects 21 historical functions with 19 explicit
postconditions. Two previously selected TTL/expiry helpers have no direct
`ensures`; this increment adds ten postconditions. Source observations (SQL
rows, parsed UUID-to-u128 conversion, status/mode decoding, nonce comparison,
signature verification, clocks and sled challenge consumption) and actual
SQL/token effects remain outside these pure proofs. Rejection paths that return
before construction remain Rust glue; the new constructors do not prove
complete handler traces.

## Challenge purpose refinement (F-1)

`challenge::StoredTag` is a bounded nine-byte buffer plus the real stored
length. `purpose_stored_tag` and `purpose_tag_bytes` are the only issuers of the
three tags. `classify_stored_tag` compares only the significant bytes for the
recognized lengths (5, 6, 9); padding past `len` is not part of the value, and a
longer or mutated value cannot match. `stored_tag_from_bytes` retains the real
length while copying at most nine bytes, so truncation cannot turn a long value
into a short tag. `consume_challenge` in `vela-server` now performs the
effectful `get_del` and feeds the returned bytes to `classify_consumption`;
`take_challenge` exposes the same decision to the login driver. All three
existing consumers (`/auth/verify`, `/device/enroll`,
`/web-session/:id/token`) use the same pure classifier, and the historical
status/message/default-purpose behavior is unchanged.

The hand-written module
`proofs/fstar/challenge-lemmas/Vela_session_policy_challenge_lemmas.fst`
restates recognition as literal byte values and lengths, independent of the
Rust helpers, and proves the extracted classifier and consumption decision
equal that raw-byte specification for **every** bounded tag. It also proves an
accepted consumption carries the expected purpose's raw bytes and that a
present non-matching tag is always `WrongPurpose`.

## `/auth/verify` login driver (F-2)

`login_driver` owns the per-request decision sequence used by
`vela-server/src/auth/verify.rs`:

1. `begin_login` requests the single-use challenge take.
2. `on_challenge_taken` requires the actual `classify_consumption` result to be
   `Accepted`; `Missing`, `WrongPurpose` and a `get_del` error are terminal.
3. `on_device_looked_up` requires a present, unrevoked, decoded device row.
4. `on_verifier_finished` requires the actual verifier result to be `Valid`;
   a decode failure is terminal without the failure-counter side effect, and a
   rejection enters `RecordVerificationFailure`.
5. `on_failure_record_observed` records the log-only exponential-backoff
   attempt and the request-level fallback limiter result, then fails.
6. `on_backoff_reset_observed_event` requires a successful reset.
7. `on_token_issue_observed` requires the existing verified
   `TokenService::issue` to succeed.
8. `on_token_track_observed` requires JTI tracking before `Respond`; a tracking
   failure discards the token and returns the tracking error.

The handler checks every next effect in release builds, including the initial
challenge take and final `Respond`. Unexpected effects fail closed with an
internal error. It carries original errors through the corresponding failure
category, preserving the original status/message precedence: challenge messages, the uniform
`DEVICE_AUTH_FAILED` message, verifier `BadRequest`/`Internal` pass-through,
the fallback limiter's own error, backoff-reset errors, issuance errors and
tracking errors. The `last_active` update remains unconditional handler glue
and is not part of the decision driver.

The Rust postconditions are local: `login_state_is_sound` and
`login_effect_is_sound` tie each stage to the facts it implies and make
`Respond` require the full successful chain; `step` preserves soundness and
emits only effects its pre-state supports. The hand-written module
`proofs/fstar/login-driver-lemmas/Vela_session_policy_login_driver_lemmas.fst`
restates the invariant independently, proves it equivalent to the Rust
predicate, and proves by induction over arbitrary `list t_LoginEvent`:

- every trace from `begin_login` stays sound;
- at most one `Respond` effect per request, and a finished driver is inert;
- a response implies the event list contains an accepted `login` challenge
  event, a `Valid` verifier event, and a `Tracked` JTI event;
- a wrong-purpose or missing challenge, an actual verifier rejection, and a
  tracking failure are terminal and cannot be followed by a response;
- real success, wrong-purpose refusal, verifier refusal and tracking-failure
  witnesses are reachable.

Two proof-level mutation checks (logs in the evidence directory) modify a
**copy** of the extracted driver: making `WrongPurpose` behave like `Accepted`
fails `step_challenge_flag_origin`; making `RejectedUnauthorized` behave like
`Valid` fails `step_verifier_flag_origin`. The production source is never
patched.

## Limits

- The checked login result is per request. A concurrent one-challenge
  composition (two or more requests racing for the same nonce) is **not**
  proved here; the executable
  `vela-server/tests/challenge_single_use_model.rs` covers the atomic
  `get_del`/single-use behavior for bounded traces and real concurrency. The
  per-request theorem does not claim `get_del` linearizability, SQL row/guard
  semantics, verifier soundness, PASETO security, store atomicity, or
  crash/retry behavior.
- Store/SQL results and the verifier result are explicit trusted observations.
  The driver does not claim device-revocation or token-issuance linearization.
- `record_verify_failure` is log-only in the handler; the driver's
  `FailureRecordObservation` records only the request-level fallback limiter
  result, which is the error the handler propagates.
- The historical `proofs/fstar/extraction/Vela_session_policy.fst` is
  byte-identical after the focused gate. The focused extraction must never be
  included in the same `fstar.exe` invocation as the historical one.

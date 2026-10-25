# Login driver and challenge-purpose refinement (F-1/F-2 increment)

Date: 2026-10-25
Authored on parent: `c8a377d` (`Record the first hosted iOS sync admission test pass`)
Original delegated worktree: `/home/hirew/.t3/worktrees/VELA/t3-cd2daf01`
Heavy-command wrapper: `~/.local/opt/vela-tools/bin/vela-heavy`
Target dir: `/home/hirew/.t3/worktrees/VELA/t3-700776df/target`

The original sources/evidence were cherry-picked as `40129b6` onto
`d98475f`. Historical logs below describe that delegated run, not a rerun on
the integrated tree. Its concluding “11 (3 + 8)” entry-point count is a
reporting error: the extraction selects **12 (3 challenge + 9 login)**.
The historical artifact has **19 explicit postconditions / 21 selections**;
“21 contracts” in the original log counts selected functions, not ensures.
Parent runtime-gate corrections and fresh integrated handler tests are
recorded separately in `login-driver-runtime-gates/`.

This original increment owns only:

- `serverVELA/vela-session-policy` (new `src/challenge.rs`,
  `src/login_driver.rs`, `tests/login_driver.rs`, focused extraction,
  challenge/login lemma modules, `verify-fstar-login-driver.sh`, README)
- `serverVELA/vela-server/src/auth/challenge.rs`
- `serverVELA/vela-server/src/auth/verify.rs`
- `serverVELA/vela-server/tests/login_driver_handler.rs`
- this evidence directory

No global assurance file, manifest, correspondence table, `security/formal/*`
file, or CI file is edited. The historical session-policy extraction
(`proofs/fstar/extraction/Vela_session_policy.fst`) is byte-identical.

## What changed

### Challenge stored-tag bytes

`GET /auth/challenge` still writes exactly `login`, `enroll` or `web_token`
under `challenge:<nonce>`, and still defaults to `login`. The acceptance
decision now lives in the pure production module
`vela_session_policy::challenge`:

- `StoredTag` is a bounded nine-byte buffer plus the real length;
- `purpose_stored_tag` / `purpose_tag_bytes` are the issuers;
- `classify_stored_tag` recognizes only the significant bytes of the three
  issued tags and returns `Unknown` for every other length/byte pattern;
- `classify_consumption` returns `Accepted`, `Missing` or `WrongPurpose`;
- `stored_tag_from_bytes` retains the real length while copying at most nine
  bytes, so a long value cannot be truncated into a short tag.

`vela-server`'s `ChallengePurpose` enum, `parse` behavior, default purpose,
status codes and exact error messages are unchanged. `take_challenge` performs
the atomic `get_del` and returns the pure classification; `consume_challenge`
maps it to the historical messages for all three consumers (`/auth/verify`,
`/device/enroll`, `/web-session/:id/token`). The login handler uses
`take_challenge` directly so the driver sees the actual classification.

### `/auth/verify` decision driver

This section describes the intended driver sequence. The original handler
only enforced the challenge effect at runtime; the other checks were debug
assertions. The parent [runtime-gate correction](../login-driver-runtime-gates/README.md)
now enforces every effect in release builds and retains fresh integrated tests.

`post_verify` now runs the pure `vela_session_policy::login_driver` state
machine for every decision after the existing IP limiter and backoff precheck:

1. take/classify the single-use login nonce;
2. observe the unrevoked device row;
3. decode the nonce and run the actual hybrid verifier;
4. on rejection, perform the log-only exponential-backoff record and the
   request-level fallback limiter, then return the historical error;
5. reset the success streak/backoff;
6. issue the existing verified device token;
7. track the JTI;
8. respond only after tracking.

The handler still performs every effect and renders the driver's failure
category with the original status/message precedence. The `last_active` update
remains unconditional handler glue. A tracking failure discards the issued
token and returns the tracking error; no response is produced for an untracked
token. `record_verify_failure` remains log-only; its error cannot skip the
fallback limiter.

## Rust postconditions (checked by hax/F*)

The focused gate selects these production functions:

| Function | `requires` / `ensures` |
|---|---|
| `challenge::purpose_stored_tag` | no postcondition; its literal bytes are proved by the hand-written raw-byte lemma. |
| `challenge::classify_stored_tag` | `classification_matches_spec(tag, class)`. |
| `challenge::classify_consumption` | `consumption_matches_spec(stored, expected, decision)`. |
| `login_driver::begin_login` | state sound; effect sound; stage `Challenge`; every authority/success flag false. |
| `login_driver::step` | requires sound input; ensures effect sound and preserves soundness. |
| `login_driver::on_challenge_taken` | same through `step`. |
| `login_driver::on_device_looked_up` | same through `step`. |
| `login_driver::on_verifier_finished` | same through `step`. |
| `login_driver::on_failure_record_observed` | same through `step`. |
| `login_driver::on_backoff_reset_observed_event` | same through `step`. |
| `login_driver::on_token_issue_observed` | same through `step`. |
| `login_driver::on_token_track_observed` | same through `step`. |

`login_state_is_sound` is a Rust predicate over the resulting driver:

- each non-terminal stage carries exactly the facts its position implies;
- `device_present ==> challenge_accepted`;
- `verifier_valid ==> device_present`;
- `backoff_reset ==> verifier_valid`;
- `token_issued ==> backoff_reset`;
- `token_tracked ==> token_issued`;
- `responded ==> token_tracked`;
- a response implies `challenge_accepted && device_present && verifier_valid &&
  backoff_reset && token_issued && token_tracked` and `!failed`;
- `failed` and `responded` are mutually exclusive.

`login_effect_is_sound` additionally requires an `Insert`-style exact pre-state
for every effect: `Respond` requires the full chain, `Fail` requires terminal
failure without a response, and no effect can be emitted from the wrong stage.

These are conditional on the input state being sound. That is a genuine
inductive invariant, not a hypothesis equal to the desired conclusion: the
hand-written F* module proves it independently and unconditionally for every
trace starting at `begin_login`.

## Hand-written F* lemmas (over the actual extracted driver)

### Challenge raw-byte refinement

Module:
`serverVELA/vela-session-policy/proofs/fstar/challenge-lemmas/Vela_session_policy_challenge_lemmas.fst`

It defines `raw_login`, `raw_enroll`, `raw_web_token` and `raw_classify` using
literal byte values and lengths, independent of `purpose_stored_tag` /
`same_stored_tag`. It proves for every `t_StoredTag`:

- `classify_matches_raw` — the extracted classifier equals `raw_classify`;
- `classify_consumption_matches_raw` — the extracted consumption decision
  equals the raw-byte consumption spec;
- `accepted_implies_raw_expected` — an accepted consumption carries exactly the
  expected purpose's raw bytes;
- `present_non_matching_is_wrong_purpose` — a present non-matching tag is
  always `WrongPurpose` (and the caller's `get_del` has already spent it);
- `absent_is_missing` — absence is `Missing`, never accepted.

Witnesses cover each issued tag, cross-purpose refusal and an unknown
short-length tag.

### Login trace induction

Module:
`serverVELA/vela-session-policy/proofs/fstar/login-driver-lemmas/Vela_session_policy_login_driver_lemmas.fst`

It imports the extracted `Vela_session_policy.Login_driver.step` and does not
reimplement the transition machine. It restates the invariant independently
(`trace_sound`), proves it equal to `login_state_is_sound`, then proves by
induction over arbitrary `list t_LoginEvent`:

1. `trace_sound_matches_rust` — independent invariant equals the Rust one.
2. `begin_sound` — the initial driver is sound.
3. `step_sound` — every extracted step preserves soundness.
4. `step_after_response` / `step_after_done` / `done_suffix_inert` — a finished
   request is inert for every unbounded suffix.
5. `respond_effect_requires_all` — a `Respond` effect carries the complete
   successful chain.
6. `respond_only_from_tracked` — a `Respond` effect is only the actual
   `TokenTracked Tracked` event from the `Track` stage.
7. `fail_effect_is_terminal` — every `Fail` effect is terminal, has no
   response, and every suffix is inert.
8. `step_challenge_flag_origin` / `challenge_flag_origin` — the accepted flag
   is set only by an actual `ChallengeObserved (Observed Accepted)` event.
9. `step_verifier_flag_origin` / `verifier_flag_origin` — the valid flag is set
   only by an actual `VerifierObserved Valid` event.
10. `step_tracked_flag_origin` / `tracked_flag_origin` — the tracked flag is
    set only by an actual `TokenTracked Tracked` event.
11. `respond_count_le_one` — at most one response per request for any event
    list.
12. `response_implies_accepted_event` — a response requires a consumed
    matching-purpose `login` challenge event.
13. `response_implies_valid_verifier_event` — a response requires an actual
    successful verifier event.
14. `response_implies_tracked_event` — a response requires an actual tracked
    JTI event.
15. `login_trace_theorem` — final soundness, response/failure exclusivity,
    response count ≤ 1, and the three provenance implications.
16. `wrong_purpose_is_terminal`, `missing_challenge_is_terminal`,
    `verifier_rejection_is_terminal`, `tracking_failure_is_terminal` — explicit
    terminal-refusal lemmas.
17. Reachability witnesses: full success; wrong-purpose refusal; verifier
    rejection; tracking failure with an issued-but-untracked token.

`Respond`, `Fail`, etc. are observed effects/decisions. The proof does **not**
claim that SQL/store/verifier/PASETO operations have their intended effects.
The device row, verifier result, store results and token issuance are trusted
observations. The driver does not claim device-revocation or token-issuance
linearization.

## Mutation checks

Both mutate a **copy** of the extracted driver in `/tmp/opencode`, never the
production source. The focused F* invocation is run with the mutant include
directory replacing the focused extraction include.

- `mutation-drop-purpose-check.log`: the `WrongPurpose` branch of
  `on_challenge_observed` is changed to the `Accepted` transition. The check
  fails at `step_challenge_flag_origin` — without the purpose check, a
  wrong-purpose event could set `challenge_accepted`, so the response
  provenance theorem is no longer provable.
- `mutation-drop-verifier-gate.log`: the `RejectedUnauthorized` branch of
  `on_verifier_observed` is changed to the `Valid` transition. The check fails
  at `step_verifier_flag_origin` — without the verifier gate, a rejection could
  set `verifier_valid`, so the response-requires-verifier theorem is no longer
  provable.

The unmutated focused gate discharges every verification condition; no
`assume`, `admit`, `axiom`, `--lax` or proof-goal-as-hypothesis is used.

## Tests vs proof

- `cargo-test-session-policy.log`: 15 crate unit tests plus 13 exhaustive
  login-driver tests (stage × event coverage, out-of-order inertness, soundness
  preservation, success, wrong/missing/storage challenge, device
  absent/query/parse, decode failure, verifier rejection classes, fallback
  counter error, backoff/issue failure, tracking failure, wrong-purpose and
  invalid-verifier mutation-style traces).
- `cargo-test-server-integration.log`: the full 67-test HTTP integration suite
  after the handler rewiring.
- `cargo-test-challenge-single-use-model.log`: the bounded challenge
  single-use/purpose model (depth 3) plus the real-concurrency one-success test.
- `cargo-test-login-driver-handler.log`: four focused real-handler tests —
  successful login tracks the issued JTI and replay is refused; a wrong-purpose
  login nonce is refused and spent; a failed verifier returns no token and
  records both failure-streak side effects; two current-thread, interleaved login futures with one nonce yield at most one token. The parent runtime-gate increment also exercises this on a two-worker runtime.
- `fstar-full-verify.log`: one `./verify-fstar.sh` run: historical 21-selection / 19-postcondition
  extraction/F* check followed by the focused challenge/login gate. All
  verification conditions discharged.

Tests and proof are separate evidence; neither substitutes for the other.

## Scope and open obligations

- The checked login result is **per request**. A concurrent one-challenge
  composition (two or more requests racing for the same nonce) is **not**
  proved in F* here. The bounded executable model
  `challenge_single_use_model.rs` covers the atomic `get_del`/single-use
  behavior and real concurrency, but it is not a proof. The per-request theorem
  does not claim `get_del` linearizability, SQL row/guard semantics, verifier
  soundness, PASETO security, store atomicity, or crash/retry behavior.
- Store/SQL results and the verifier result are explicit trusted observations.
  The driver does not claim device-revocation or token-issuance linearization.
- `record_verify_failure` is log-only; only the request-level fallback limiter
  result is decision-relevant and propagated.
- The `last_active` update is unconditional handler glue and is not part of the
  driver's decision trace.
- The historical 21-selection / 19-postcondition extraction is unchanged. The focused extraction
  must never share an `fstar.exe` include directory with it.

## Toolchain / commands

- hax 0.3.7, Rust `nightly-2025-11-08` (pinned by
  `serverVELA/vela-session-policy/rust-toolchain.toml`; active compiler
  `rustc 1.93.0-nightly (843f8ce2e 2025-11-07)`), F* 2025.10.06, Z3 4.13.3.
- `/tmp/vela-fstar-prebuilt/fstar` was absent in this worktree, so it was
  symlinked to the pinned
  `/home/hirew/.local/opt/vela-formal-fstar-2025.10.06/fstar` install.
- Full F* argv and source hashes: see `commands.txt`, `fstar-full-verify.log`
  and `source-hashes.txt`.
- All heavy commands used `~/.local/opt/vela-tools/bin/vela-heavy` (3 GiB / no
  swap / 1 worker). No uncapped cargo/F* command was run.

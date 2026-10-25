# Raw-byte nonce bridge

`Vela_session_policy_login_raw_nonce.fst` bridges the existing abstract
concurrent login composition to the **actual raw challenge bytes**.

The existing
`Vela_session_policy_login_driver_composition` module proves the
at-most-one-admission/response/issuance theorem over an abstract stored purpose
(`StoredPurpose_Login` / `StoredPurpose_Other`).  This module keeps the stored
nonce as the value the modelled atomic take returns, `option (t_Slice u8)`, and
computes every take decision with the **actual extracted production functions**

- `Vela_session_policy.Challenge.stored_tag_from_bytes`, and
- `Vela_session_policy.Challenge.classify_consumption`

applied to `ChallengePurpose_Login`.  Request transitions always call the actual
extracted `Vela_session_policy.Login_driver.step`; no driver transition rule is
restated.

## Model

| Real effect | Model |
|---|---|
| `Store::get_del` of `challenge:<nonce>` | `Take i`: absent (`None`) reports `Missing`; present bytes `Some b` report the actual `classify_consumption (Some (stored_tag_from_bytes b)) Login`; any present value is removed in the same step |
| `get_del` error | `TakeFailed i`: no removal, no admission |
| device row query | `Device i observation` |
| base64 decode + hybrid verifier | `Verify i observation` |
| failure-counter/backoff side effects | `Record i observation` |
| success-streak/backoff reset | `Reset i observation` |
| PASETO issuance | `Issue i observation` |
| JTI tracking | `Track i observation` |

The raw world is projected to the existing abstract composition world:

```fstar
let project (w: raw_world) : world =
  { challenge = raw_purpose w.raw_nonce;  (* actual classifier on the bytes *)
    nonce_admitted = w.raw_admitted;
    responses = w.raw_responses;
    tokens = w.raw_tokens;
    reqs = w.raw_reqs }
```

`raw_purpose` is a login purpose exactly when the actual extracted classifier
accepts the raw bytes for `ChallengePurpose_Login`; otherwise it is the
"other" purpose.  `raw_login_decision_iff_slice` connects that decision to the
checked producer lemma's literal-byte predicate `slice_is_login`
(`consumption_accepts_iff_slice`), so the connection is not an assumed
equivalence.

## Results

- `raw_literal_matches_classifier`: independent literal bytes equal the actual decision.
- `raw_non_literal_never_admits`: absent/non-login literal bytes yield no admission,
  Respond effect or successful issue observation under any schedule.
- `raw_admission_requires_literal_login`: any such admission/effect requires literal login bytes.
- `raw_run_invariant`: all driver states are sound, nonce conservation holds,
  and response/issue counters equal the corresponding driver flags.


- `project_raw_step`: projection commutes with every action.
- `project_raw_run`: projection commutes with an arbitrary `list action`
  schedule.
- `raw_one_nonce_at_most_one_admission`: for every initial raw value and every
  schedule, at most one request is accepted, at most one `Respond` effect
  occurs, at most one successful token-issue observation occurs, and
  `nonce_admitted + present <= 1`.
- `raw_at_most_one_accepted`, `raw_at_most_one_respond`,
  `raw_at_most_one_successful_issue`: the three observations named separately.
- `raw_non_login_never_admits`: if the actual classifier does not accept the
  initial raw value for login (`raw_is_login nonce0 = false`), then no schedule
  admits a request, emits Respond, or counts a successful issue observation.
- Witnesses over concrete raw values, with checked producer lemmas:
  successful login (`concrete_login`), wrong purpose (`purpose_tag_bytes
  Enroll`), unknown/long bytes (`concrete_long`, ten bytes, no truncation),
  absent nonce, two-request contention on one raw `login` value, and a
  `get_del` failure that preserves the nonce.

## Interface assumptions and limits

Proved here: the conditional conjugation of the actual extracted driver and the
actual extracted raw-byte classifier, plus the projection into the existing
abstract composition.

Not proved here:

- `get_del` linearizability, sled atomicity or durability;
- that the nonce key identifies exactly one stored challenge;
- that the handler's real store bytes are the modelled `t_Slice u8` and that
  the handler passes exactly those bytes to `stored_tag_from_bytes` /
  `classify_consumption` (the Option/Vec glue is assumed);
- that the handler performs exactly the effect the driver returns, and that an
  observation reaches the driver in the same step as its effect;
- OS, SQL row/guard semantics, verifier soundness, PASETO security, JTI
  persistence, clocks, TTL, crash/retry behaviour, or revocation
  linearization;
- any refinement theorem from Rust/sled handler code to this model.

The raw slice is the modelled take result, not a proof about the store.  No
`assume`, `admit`, `axiom`, `--lax`, `opaque`, local `val`, or goal-as-hypothesis
is used. The
[standalone runner](../../../verify-fstar-login-raw-nonce.sh); it adds **zero** Rust
postconditions.  Evidence is under
`security/assurance/proof-logs/current/login-raw-nonce-bridge/`.

The aggregate session verifier also includes this module in its existing
focused invocation after fresh extraction. The standalone runner checks
existing inputs without regeneration. The original evidence is from
`09d991c` on `1902ecd`; later parent scope-comment/reporting corrections to
reused inputs are identified by the integrated parent replay.

The at-most-one bound is purpose-agnostic; it does not establish the correctness
of the classifier. `raw_non_literal_never_admits` instead starts from the
independent literal predicate and uses its checked equivalence to the actual
classifier. `raw_admission_requires_literal_login` gives the converse necessity
for admission, Respond effects or successful issuance observations.
`raw_run_invariant` exposes the complete transported invariant. These four
post-review lemmas bring this module to 44; original logs retain 40.

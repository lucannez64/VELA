# Raw-byte nonce bridge (F*)

This evidence directory backs the new module

`serverVELA/vela-session-policy/proofs/fstar/login-raw-nonce-lemmas/Vela_session_policy_login_raw_nonce.fst`

and the standalone runner

`serverVELA/vela-session-policy/verify-fstar-login-raw-nonce.sh`.

The module bridges the existing abstract concurrent composition
(`Vela_session_policy_login_driver_composition`) to the **actual raw challenge
bytes** and the **actual extracted classifier**, without claiming a sled or
handler refinement theorem.

The original run is `09d991c` on `1902ecd`, cherry-picked as `5d68185`
onto hosted-green `8d3610d`. Original hashes and logs retain that delegated
snapshot; inherited scope-comment/echo corrections in reused modules are not
proof-body changes. The parent aggregate replay records current inputs and
checks all seven modules after fresh extraction. This is pure model bridging,
not actual store/handler refinement.

## Base and scope

- Base commit: `1902ecd30ce7b41fa400cdfbebf387f49144ffd1`
  (`Record integrated byte-producer and nonce proofs with precise trust
  boundaries`).
- Worktree: `/home/hirew/.t3/worktrees/VELA/t3-af324129`.
- New files only:
  - `proofs/fstar/login-raw-nonce-lemmas/Vela_session_policy_login_raw_nonce.fst`
  - `proofs/fstar/login-raw-nonce-lemmas/README.md`
  - `verify-fstar-login-raw-nonce.sh`
  - this evidence directory.
- Not edited: existing Rust, existing extracted F* modules, existing proof
  modules, `verify-fstar-login-driver.sh`, `verify-fstar-login-composition.sh`,
  `verify-fstar.sh`, the aggregate verifiers, `security/assurance/run-all.sh`,
  manifests, correspondence/global assurance docs, CI, or handlers.
- Parent uncommitted changes in the sibling worktree are comments/echo/evidence
  only; this worktree's base is `1902ecd` and no existing model body was
  changed here.

## The bridge

The existing composition's take interface exposes only
`StoredPurpose_Login` / `StoredPurpose_Other`, and its README correctly says the
purpose bit is an interface parameter.  This module removes that parameter at
the nonce boundary:

- The stored raw nonce is `option (t_Slice u8)` — the modelled value returned
  by the atomic take (`None` for absent, `Some b` for the exact stored bytes).
- On `Take i`, a present value is classified by the **actual extracted**
  functions:

  ```fstar
  raw_login_decision b =
    classify_consumption
      (Option_Some (stored_tag_from_bytes b))
      ChallengePurpose_Login
  ```

  `stored_tag_from_bytes` is the production byte-to-tag conversion;
  `classify_consumption` is the production expected-purpose decision.
  `Missing` is impossible for a present value and is proved so; the tiny
  coercion in `present_consumption` is the identity on every reachable
  present decision.
- Every request transition calls the **actual extracted**
  `Vela_session_policy.Login_driver.step` through `raw_deliver`.  No transition
  rule is restated.
- The raw world is projected to the existing abstract world by deriving the
  abstract purpose from the same actual decision:

  ```fstar
  raw_purpose None = None
  raw_purpose (Some b) =
    Some (if raw_login_decision b = Accepted
          then StoredPurpose_Login
          else StoredPurpose_Other)
  ```

- `project_raw_step` proves the projection commutes with **every action**;
  `project_raw_run` proves it commutes with an **arbitrary `list action`
  schedule** by induction on the schedule.  This is a genuine composition of
  the two layers, not an appeal to "two proofs compose".

The raw-purpose connection is established from actual functions and checked
producer lemmas:

- `classify_consumption_some` is the definitional unfolding of the extracted
  decision for a present tag (it adds no decision rule).
- `raw_decision_not_missing` shows the coercion is unreachable.
- `raw_login_decision_iff_slice` uses the checked producer lemma
  `consumption_accepts_iff_slice` to prove the actual decision accepts exactly
  the checked literal-byte predicate `slice_is_login`.
- `raw_purpose_iff_slice` lifts that to the whole raw purpose.
- The concrete successes/refusals use `concrete_login_classified`,
  `concrete_long_is_unknown`, `issued_classified`, and
  `issued_path_accepts_only_its_purpose` from the checked lemma modules.

No target equivalence is assumed. Cardinality transport is purpose-agnostic:
it holds even for a classifier with incorrect literal semantics. The literal
link supplies byte meaning separately; post-review general literal-refusal
and admission-requires-literal lemmas make that link part of their proof.

## Results

All general schedule-safety results quantify over arbitrary initial raw values and schedules
(`list action`, i.e. arbitrary request counts and schedule lengths).

- `project_raw_step`: projection commutes with each action.
- `project_raw_run`: projection commutes with arbitrary schedules.
- `raw_one_nonce_at_most_one_admission`:
  - `raw_responses <= 1` (at most one `Respond` effect),
  - `raw_tokens <= 1` (at most one successful token-issue observation),
  - `accepted_count raw_reqs <= 1` (at most one accepted request),
  - `responded_count <= 1`, `issued_count <= 1`,
  - `b2n raw_admitted + raw_present raw_nonce <= 1` (one nonce is either still
    stored and marked admitted cannot both hold; this inequality alone does not assert exactly one accepted request).
- `raw_at_most_one_accepted`, `raw_at_most_one_respond`,
  `raw_at_most_one_successful_issue`: the three named observations separately.
- `raw_non_login_never_admits`: if `raw_is_login nonce0 = false` (the actual
  classifier does not accept the initial raw value for login), then no schedule
  admits a request, answers with a response, or issues a token.
- `raw_non_login_purpose_never_admits`: the same refusal with the projected
  abstract-purpose premise.

## Witnesses

The checked witnesses are not vacuous; each is a concrete raw value and a
concrete schedule.

| Witness | Raw value | Result |
|---|---|---|
| `raw_success_is_reachable` | checked `concrete_login` (`login`) | take admits; final one Respond effect, one successful token-issue observation, one accepted/responded/issued |
| `raw_wrong_purpose_spends_nonce` | actual `purpose_tag_bytes Enroll` | actual classifier returns `WrongPurpose`; nonce spent; no admission/response/token |
| `raw_long_unknown_is_refused` | checked `concrete_long` (`login` + five `!`, length 10) | retained length 10, classifier `Unknown`, nonce spent, no admission/response/token |
| `raw_missing_nonce_is_terminal` | `None` | `Missing`; no admission/response/token |
| `raw_two_request_contention` | checked `concrete_login`, two requests | one accepted, one Respond effect, one successful token-issue observation; second request cannot take the spent nonce |
| `raw_take_failure_preserves_nonce` | checked `concrete_login` | a failed take leaves the raw nonce for a later successful take |

## Verification

Successful run: `fstar-verify.log`, exit 0.

- F* 2025.10.06, Z3 4.13.3, hax 0.3.7, rustc nightly 2025-11-08 channel.
- `--cache_off`, `--z3rlimit 16000`, shared hax proof libraries.
- Seven modules verified: two focused extraction modules and five hand-written
  proof modules.
- Shared source policy:
  `security/formal/check-driver-proof-sources.py` over every local F* source
  directory used in resolution plus the verifier cwd; result: "2 extracted
  modules, 5 proof modules; no unreviewed escapes/options".
- No `assume`, `admit`, `axiom`, `--lax`, `opaque`, local `val`, or
  proof-goal-as-hypothesis.
- Every proof input is hashed before and after F*; the run fails if any byte
  moves.  The historical extraction is hash-guarded but not passed to F* (the
  focused partial root modules would shadow it).

## Mutation checks

Both mutations are in `/tmp` copies; the checked-in module and all inputs were
unchanged.  Both are rejected by F*.

- Mutation A (`mutation-A.diff`): `raw_purpose` loses the actual decision and
  always returns `StoredPurpose_Login`.  F* rejects at
  `raw_purpose_some_other` (mutant line 121).  This shows the projection's
  purpose mapping must follow the actual classifier.
- Mutation B (`mutation-B.diff`): `raw_login_decision` ignores the raw bytes
  and always converts `purpose_stored_tag ChallengePurpose_Login`.  F* rejects
  at `raw_login_decision_iff_slice` (mutant line 162).  This shows the take
  literal-byte link and refusal witnesses depend on reading the actual bytes.
  It does not invalidate the purpose-agnostic at-most-one bound.

Logs and exact argv are in
`mutation-A-purpose-always-login.log`, `mutation-B-copy-path-ignores-bytes.log`,
`mutation-A-argv.txt`, `mutation-B-argv.txt`, and `mutation-commands.txt`.

## Explicit assumptions and non-claims

This is a **pure model bridge**.  The following are retained as interface
assumptions, not proved here:

- `get_del` linearizability/atomicity and durability; the nonce key identifies
  exactly one stored challenge.
- The handler observation/effect fidelity: the handler performs exactly the
  effect the driver returns, and an observation reaches the driver in the same
  step as its effect.
- The `Option`/`Vec` actual glue: the real store value (`Option<Vec<u8>>` or
  equivalent) is faithfully represented by `option (t_Slice u8)`, and the
  handler passes exactly those bytes to `stored_tag_from_bytes` and
  `classify_consumption`.  This is not proved from Rust.
- No OS/sled refinement, SQL row/guard semantics, verifier soundness,
  PASETO security, JTI persistence, TTL/expiry, crash/retry behaviour, clocks,
  revocation linearization, or handler/handler-error refinement theorem.
- The `raw_admitted` bit is a model of "this nonce was consumed by an accepted
  login take", not a store fact.
- No claim that the actual handler or actual sled bytes satisfy this model;
  the raw slice is the modelled take result.

## Counts and hashes

See `counts.txt` and `source-hashes.txt`.  In particular:

- new Rust postconditions/contracts: **0**;
- new extracted F* modules: **0** (the two focused modules are inputs and are
  byte-identical);
- new hand-written F* proof modules: **1**;
- existing F*/Rust modules edited: **0**;
- script index mode: `100755`;
- two mutation checks, both rejected.

## Reproduction

From `serverVELA/vela-session-policy`, with the environment in `commands.txt`:

```
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-login-raw-nonce.sh
```

The runner is standalone and is not wired into the aggregate verifier,
manifests, correspondence, or CI in this change.

## Post-review strengthening

The original snapshot has 40 lemmas. Its general cardinality theorem is
purpose-agnostic, and the literal link was originally separate from the
general refusal theorem. Parent corrections add four lemmas: literal/classifier
equivalence for optional values, refusal of any absent/non-literal initial
value for all schedules, admission/effect requiring literal login bytes, and
the full raw run invariant. The new refusal theorem explicitly calls the
literal bridge, and the successful witness also instantiates its necessity
corollary. The current module has 44 lemmas; original raw logs/hashes above
remain the 09d991c snapshot. Current verification is recorded separately in
[the parent replay](../login-raw-nonce-integrated/README.md).

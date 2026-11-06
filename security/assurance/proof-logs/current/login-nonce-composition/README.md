# Historical concurrent login nonce composition (F*)

`serverVELA/vela-session-policy/proofs/fstar/login-driver-composition/Vela_session_policy_login_driver_composition.fst`
composes the extracted `Vela_session_policy.Login_driver.step` across any
number of concurrent `/auth/verify` requests sharing one challenge nonce.

This increment adds a **new composition module**, a **standalone verification
script**, and this evidence directory. It does not edit `src/` Rust, the
challenge/login lemma modules, `verify-fstar-login-driver.sh`,
`verify-fstar.sh`, handlers, CI, manifests, correspondence, or global docs.
This describes the original `d58e5bd` run on `3aaac25`, cherry-picked as
`63a2b64`. Hashes retain that original pre-producer snapshot. Parent integration
preserves the actual step and adds the new producer lemma dependency; scope
comments and verifier wiring have subsequent corrections. The composition is
checked in the existing focused invocation after fresh extraction, avoiding a
second extraction/check cycle. The standalone runner remains for targeted checks.

The current six-module source set is reproduced in the
[integrated parent evidence](../login-integrated-proofs/README.md). The original
`fstar-verify.log`, `source-hashes.txt`, commands and mutation argv here are
historical evidence for `d58e5bd`, not a current-head replay. Its 101 total
handwritten lemma declarations predate the producer addition; the integrated
source set has 124 (13 bounded challenge + 23 producer + 28 login + 60
composition). Response counters count returned Respond effects; token counters
count successful issuance observations, not IssueToken effects or real handler
operations. Actual effects require the stated fidelity assumption.

## Inputs

- Base commit: `3aaac25` (`Run login proof gate with reviewed source policy`).
- Focused extraction:
  - `proofs/fstar/extraction-login-driver/Vela_session_policy.Challenge.fst`
  - `proofs/fstar/extraction-login-driver/Vela_session_policy.Login_driver.fst`
- Historical extraction, **not passed to fstar.exe and byte-identical**:
  - `proofs/fstar/extraction/Vela_session_policy.fst`
- Reused proof modules:
  - `proofs/fstar/challenge-lemmas/Vela_session_policy_challenge_lemmas.fst`
  - `proofs/fstar/login-driver-lemmas/Vela_session_policy_login_driver_lemmas.fst`
- New composition:
  - `proofs/fstar/login-driver-composition/Vela_session_policy_login_driver_composition.fst`

The composition calls the actual extracted `step`. It does not restate the
transition relation and does not assume the goal.

## Model

One schedule is an arbitrary `list action`. Actions start requests, take the
one nonce, fail a take, or deliver an observation to any request. The world
tracks the stored purpose, an admission bit, response and successful-issuance
counters, and the per-request drivers.

- `Take` models the atomic `get_del`: a present nonce is removed in the same
  step; `Accepted` is returned only for a login tag, `WrongPurpose` for any
  other tag, `Missing` when absent.
- `TakeFailed` models a `get_del` error and leaves the nonce in place.
- `Device`, `Verify`, `Record`, `Reset`, `Issue`, `Track` deliver the
  corresponding extracted observation.
- There is no action that inserts a fresh challenge: the theorem is about one
  nonce key.

## Results

- `one_nonce_at_most_one_admission`: for every initial purpose and every
  schedule, one nonce admits at most one request, produces at most one
  `Respond` effect, and flips the token-issued flag at most once.
- `non_login_nonce_never_admits`: if the nonce is absent or carries a
  non-login purpose, no schedule admits a request, responds, or issues a token.
- Witnesses (checked): complete success; two-request contention; wrong-purpose
  spending; absent nonce; `get_del` failure preserving the nonce for a later
  request; verifier rejection; tracking failure after a token was issued.

The proof is an unbounded structural induction over the schedule. Per-request
flag deltas are derived from the extracted `step` (`step_accepted_delta`,
`step_responded_delta`, `step_issued_delta`) and combined with generic list
update/count lemmas. Nonce conservation is
`b2n nonce_admitted + challenge_present <= 1`; admission bounds the accepted
count, and per-request soundness bounds responses and successful issuances.

## Counts (separate from Rust postconditions)

- New hand-written composition declarations with `Lemma`: **60** (helpers,
  state/effect accounting, headline theorems, and step-by-step witnesses).
- Reused challenge lemma declarations: 13; reused login lemma declarations: 28
  (both unchanged).
- Total proof declarations checked in the one `fstar.exe` invocation: **101**.
- **New Rust postconditions: 0.** The focused extraction is an input, not a
  product; the script does not invoke hax.

## Toolchain and exact invocation

- F* 2025.10.06, Z3 4.13.3, hax 0.3.7, Rust nightly-2025-11-08
  (`rustc 1.93.0-nightly (843f8ce2e 2025-11-07)`).
- `fstar.exe --cmi --cache_off --warn_error -331 --z3rlimit 16000
  --z3version 4.13.3 ...`; the full argv is in `fstar-verify.log`.
- Every heavy command ran through
  `~/.local/opt/vela-tools/bin/vela-heavy` (global lock, 3 GiB, no swap, one
  worker). `CARGO_TARGET_DIR` was
  `/home/hirew/.t3/worktrees/VELA/t3-700776df/target`; the run needs no Cargo
  build target because it reuses the checked-in extraction.
- The shared guard `security/formal/check-driver-proof-sources.py` accepted the
  two extracted modules and three proof modules. All local F* source
  directories used, including the verifier cwd, were enumerated. Only the
  reviewed `#push-options "--fuel 4 --ifuel 2"` / `#pop-options` witness scope
  is present; no unreviewed source option is used.
- `fstar-verify.log` ends with `All verification conditions discharged
  successfully`.

## Historical extraction identity

The script hashes `proofs/fstar/extraction/Vela_session_policy.fst` before and
after the run. Both hashes are the same in `fstar-verify.log`:

```
f558711ac3d165952846d03d1d7b2b91186fa3ff1925a0780b35fdf824f2dd1d
```

The two focused extraction modules and the existing lemma modules also keep
their hashes; see `source-hashes.txt`.

## Mutation checks (production module never patched)

**A. Reusable challenge state** (`mutation-reusable-challenge.log`): in a
temporary copy, the accepted `Take` keeps `w.challenge` instead of removing it.
F* rejects `world_step_inv` with `Assertion failed`; the nonce conservation
bound is violated because the nonce remains present after admission.

**B. Accept a non-login challenge** (`mutation-wrong-purpose-accepted.log`): in
a temporary copy, the `Some StoredPurpose_Other` take returns `Accepted`
instead of `WrongPurpose`. F* rejects `world_step_no_login` with `Could not
prove post-condition`; the purpose-isolation theorem cannot allow a non-login
challenge to admit a request. This is the "accepted without the matching
take/purpose" mutation.

Exact replacement text and invocation are in `mutation-commands.txt`.

## Comparison with the existing composition patterns

| Driver | Single-use object | Conservation result | Distinguishing effect |
|---|---|---|---|
| `vela-recovery-policy` redemption | enrollment grant | at most one device row per grant | guarded insert, restore, TTL expiry |
| `vela-recovery-policy` possession | proof state | at most one grant per proof state; at most `k` counted attempts | attempt budget, live-account/recheck |
| `vela-share-policy` | linked share/inbox | inbox quota; revocation finality | guarded SQL update/delete |
| this login module | challenge nonce | at most one admitted request, response and successful issuance per nonce | purpose-specific take, issuance/tracking failure |

The structural approach is the same as the reviewed compositions: arbitrary
schedule, shared world, per-request soundness, and token/flag conservation over
the extracted `step`. Login has no restore step: a matching or wrong-purpose
take irreversibly spends the nonce, and a tracking failure can leave an issued
token without a response.

## Assumptions and open obligations

Proved: the conditional composition over the extracted driver and the modelled
atomic take.

Not proved:

- `get_del` linearizability, sled atomicity/durability, or that the nonce key
  identifies exactly one stored challenge;
- that the real handler's stored bytes and classifier produce the modelled
  purpose (the challenge lemma module proves the classifier against literal
  bytes; here the result is the take interface);
- SQL row/guard semantics, device revocation, hybrid verifier soundness,
  PASETO security, JTI persistence, crash/retry, clocks, or revocation
  linearization;
- that the handler performs exactly the effect the driver returns, or that an
  observation reaches the driver in the same step as its effect.

No full SQL/store/JTI/PASETO/OS refinement is claimed. The `nonce_admitted` bit
is a model of "the one nonce has been consumed by an accepted login take", not
a store fact.

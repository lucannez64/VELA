# Enrollment preflight and possession/enrollment fact-construction increment

## Current review-correction run (baseline `5361406`)

This run corrects the preflight specification in `src/lib.rs` only; it does not
edit `vela-server/src/recovery/enroll_device.rs` and does not change integration
behavior. The production predicate remains the historical nested if-chain. An
independent ranked guard table plus first-true fold now states the ordering
separately, and checked lemmas prove the production rejection equals the first
applicable entry, that `Ready` implies every positive readiness guard and the
observed grant's epoch/possession fields and conversely, and parametric
adjacent-precedence/overlap facts including commitment/credential disjointness.
The enumeration test now uses its own independent table/fold oracle.

`verify-fstar.sh` selects **90** functions; the extraction contains **90**
`ensures` postconditions and **0** `assume`/`admit`/`--lax` declarations.
Eleven checked ordering/readiness lemmas are new beyond the prior eight
contracts. The exact generated artifact is
`proofs/fstar/extraction/Vela_recovery_policy.fst`
(sha256 `eaf1148be9567b8d8d6dbca8ceca3a4369df8b3c3856f19afc2de9eeee070327`);
it was not hand-edited.

The crate's 7 unit tests and 8 observation-enumeration tests passed. The server
integration/logs from `5361406` remain the applicable evidence because no
handler or server test changed; this correction only reruns the policy crate and
the 90-contract F* check. Raw output is preserved under
[`security/assurance/proof-logs/current/recovery-enrollment-preflight/delegated/`](../../../../security/assurance/proof-logs/current/recovery-enrollment-preflight/delegated/).

## Prior integrated preflight run (baseline `350cd57`)

The original increment added the production-used preflight/sequencing kernel in
`src/lib.rs` and wired `vela-server/src/recovery/enroll_device.rs` through it.
That run selected **79** functions with **79** ensures and **0**
`assume`/`admit`/`--lax` declarations, and added the preflight decision plus
seven rejection/unknown negative theorems. The superseded artifact hash was
`c3a4d03995c24ec0739da16f483c458d8714b2666df6e52d1ce0bdad90f7c828`.

The crate's 7 unit tests and 8 observation-enumeration tests passed. The
server integration suite passed 63/63, including the missing-grant privacy
test, the key-validation precedence test and the credential/commitment
restaging characterizations.
`recovery_lifecycle_model` passed 3/3.

## Historical possession/enrollment run

Local evidence for the commit based on `5fa4e9f`. The archived
[`Vela_recovery_policy.fst`](../../../../security/assurance/proof-logs/current/recovery-possession-enrollment/delegated/Vela_recovery_policy.fst) is the exact output of this delegated run
(sha256 `ae460bda3a59d2662f79aa39bfaa8093e70654385b4967f508cf590055dfcb1f`)
and was not hand-edited. The parent subsequently changed the enrollment
observation to carry actual decoded key lengths and re-extracted/rechecked all
71 contracts. That 71-contract extraction is historical; the current preflight artifact has
79 contracts. See the parent
[evidence](../../../../security/assurance/proof-logs/current/recovery-possession-enrollment/README.md).

## Historical delegated run (t3-14097854): toolchain and limits

- hax 0.3.7 (`cargo-hax`, `hax-engine` pinned to the local 0.3.7 source)
- Rust nightly-2025-11-08 (the workspace pin used by hax)
- F★ 2025.10.06 (`/tmp/vela-fstar-prebuilt/fstar/bin/fstar.exe`)
- Z3 4.13.3
- Every heavy command ran alone through
  `~/.local/opt/vela-tools/bin/vela-heavy` (global lock, 3 GiB, no swap, one
  Cargo worker) with `VELA_STEP_TIMEOUT=600`. The parent's warm
  `t3-700776df/target` was reused through `CARGO_TARGET_DIR`; the logs show the
  delegated sources compiled from sibling worktree `t3-14097854`, not from
  the parent checkout. That parent run is historical; the current preflight snapshot is documented above.

## Historical delegated inventory

`verify-fstar.sh` selects **71** functions; the extraction contains **71**
`ensures` postconditions and **0** `assume`/`admit`/`--lax` declarations. 29 are
new in this increment:

- 8 possession-initiation observation/composition/negative contracts;
- 10 possession-recovery observation/composition/negative contracts;
- 11 enrollment observation/composition/negative contracts.

`fstar.log` ends with `All verification conditions discharged successfully`.
The crate's 6 unit tests and 6 observation-enumeration tests passed in the same
run. `server-lib-tests.log` records the two real-store insertion regressions
(recovery challenge and possession proof state). `integration-possession.log`,
`integration-recovery.log` and `integration-enroll.log` record the passing
handler tests, including the new possession-grant enrollment case.

## Mapped decoded state

- Possession initiation observes account/share presence, the decoded
  `recovery_auth_hash` length, `rekey_state`, an observed free attempt slot and
  the actual TTL.
- Possession recovery observes the consumed attempt (`Missing`/`Consumed`),
  the decoded envelope's user/attempt identity, the decoded commitment length
  and epoch, the live normalized `users.key_epoch`, the rekey column and the
  hybrid verification result.
- Enrollment observes whether a grant was present, consumed and equal to the
  pre-redemption grant, the decoded possession marker and credential id, the
  decoded commitment length, decoded key lengths, the rekey column and both
  normalized epochs.

## Behavior

One fail-closed tightening: a row whose `recovery_auth_hash` decodes to zero
bytes no longer yields a possession challenge (the old code issued a challenge
that could never verify). Possession proof-state insertion now uses
`set_ex_nx`, so an observed-free slot cannot overwrite a concurrent winner.
Every other recovery status class, message and precedence is unchanged.

## Still trusted / remaining gaps

- Observation origins remain unverified glue: SQL row/text/`i64` extraction,
  `Store::get`/`get_del`/`exists`/`set_ex_nx` atomicity, base64 and JSON/serde
  decoding, UUID generation, `getrandom`, the hybrid possession verifier,
  rate limiting, clocks and TTL expiry. The policy proves the conditional
  mapping from these observations, not that they are produced correctly.
- Enrollment's account/epoch/rotation/credential/commitment rejections now go
  through the checked preflight kernel. The ordering proof is a universal
  equality between the production if-chain and an independently stated ranked
  table/fold; the readiness proof ties `Ready` to positive guards and permit
  fields in both directions. The kernel still proves only the decision and
  permit construction, not the handler's SQL/store effects or the insert guard.
  Other handlers still return errors before their constructors run (missing
  row/attempt, rotation, missing commitment, unverified assertion/proof, failed
  grant load). Negative constructor theorems do not establish those
  early-return traces.
- The preflight commitment guard and credential guard are disjoint by grant
  type, so the table's commitment-before-credential order is not a reachable
  overlap. The policy proves that disjointness; it does not prove the
  effectful `get_del`/SQL behavior or permanent revocation.
- Enrollment `user_matches` is the store-key user binding (the grant value
  carries no user id); it is not an independent decoded identity comparison.
- Early credential/commitment rejection leaves the grant unconsumed. The grant
  value embeds no user id, commitment digest/generation or split id, so
  restoring the credential or restaging any non-empty commitment revives the
  same grant within its TTL. The policy does not prove permanent revocation or
  exact commitment binding.
- Commitment/credential lengths are observed decoded values; the policy does
  not validate a scheme-specific commitment size (legacy 32-byte v1 and
  2624-byte v2 both remain possible).
- Epoch normalization retains the legacy missing/non-positive fallback; it
  does not prove stale-epoch rejection beyond equality with the decoded
  commitment/grant epoch.
- No full handler/I/O, native, protocol or full-system theorem is claimed.
  Hosted CI has not rerun this increment.

## Superseded delegated handoff

At delegated-run time, based on `5fa4e9f`, the parent-owned gate still expected
42 recovery contracts; this worktree alone therefore reported the expected
42-versus-71 drift. The standalone increment would have moved 173/180 to
202/209. That is not the integrated inventory: the parent's web-session work
adds another ten contracts. The parent has now updated the gate, correspondence
and manifest, and checks pass with **212 postconditions / 219 selected functions**
(71 recovery contracts, zero local `assume val`). This review correction raises
the recovery crate to 90 contracts (+11), so the parent must recompute the
global totals; no global manifest or correspondence file was edited here.

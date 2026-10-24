# Possession and enrollment fact-construction increment

Local evidence for the commit based on `5fa4e9f`. The checked-in
`../fstar/extraction/Vela_recovery_policy.fst` is the exact output of this run
(sha256 `ae460bda3a59d2662f79aa39bfaa8093e70654385b4967f508cf590055dfcb1f`)
and was not hand-edited.

## Toolchain and limits

- hax 0.3.7 (`cargo-hax`, `hax-engine` pinned to the local 0.3.7 source)
- Rust nightly-2025-11-08 (the workspace pin used by hax)
- F★ 2025.10.06 (`/tmp/vela-fstar-prebuilt/fstar/bin/fstar.exe`)
- Z3 4.13.3
- Every heavy command ran alone through
  `~/.local/opt/vela-tools/bin/vela-heavy` (global lock, 3 GiB, no swap, one
  Cargo worker) with `VELA_STEP_TIMEOUT=600`. The parent's warm
  `t3-700776df/target` was reused through `CARGO_TARGET_DIR`; the logs show the
  current sources compiled from this worktree.

## Inventory

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
- Several handlers still return errors before the constructor runs (missing
  row/attempt, rotation, missing commitment, unverified assertion/proof,
  failed grant load). Negative constructor theorems do not establish those
  early-return traces.
- Enrollment `user_matches` is the store-key user binding (the grant value
  carries no user id); it is not an independent decoded identity comparison.
- Commitment/credential lengths are observed decoded values; the policy does
  not validate a scheme-specific commitment size (legacy 32-byte v1 and
  2624-byte v2 both remain possible).
- Epoch normalization retains the legacy missing/non-positive fallback; it
  does not prove stale-epoch rejection beyond equality with the decoded
  commitment/grant epoch.
- No full handler/I/O, native, protocol or full-system theorem is claimed.
  Hosted CI has not rerun this increment.

## Parent-owned follow-up

`security/assurance/proof-boundary.json` still expects 42 postconditions for
`Vela_recovery_policy.fst`, so `python3 security/assurance/check-proof-boundary.py`
now fails with `expected 42 postconditions, found 71`. The parent owns that
manifest and the global counts/docs: the recovery artifact and total should move
42 → 71 and 173 → 202 postconditions, with 180 → 209 selected functions (the
same seven selected spec/comparison functions remain without `ensures`).

# Recovery enrollment preflight: local evidence

Delegated increment on baseline `350cd57` in worktree `t3-751c3edd`. It adds a
production-used verified preflight/sequencing kernel for
`serverVELA/vela-server/src/recovery/enroll_device.rs` and wires the real
handler through it. The delegated run made no push, PR, global assurance, correspondence or
manifest edit. Parent integration updates those inventories separately.

## Artifact and contracts

- Selectors in `serverVELA/vela-recovery-policy/verify-fstar.sh`: **79**
- `ensures` postconditions in the generated extraction: **79**
- Local `assume`/`admit`/`--lax` declarations: **0**
- Fresh artifact (exact, not hand-edited):
  [`Vela_recovery_policy.fst`](Vela_recovery_policy.fst)
- SHA-256: `c3a4d03995c24ec0739da16f483c458d8714b2666df6e52d1ce0bdad90f7c828`
- The checked-in extraction
  `serverVELA/vela-recovery-policy/proofs/fstar/extraction/Vela_recovery_policy.fst`
  is the same file.

Eight contracts are new:

1. `plan_enrollment_preflight`
2. `missing_preflight_grant_can_be_ready`
3. `unqueried_preflight_account_can_be_ready`
4. `absent_preflight_account_can_be_ready`
5. `epoch_mismatched_preflight_account_can_be_ready`
6. `rekeying_preflight_account_can_be_ready`
7. `replaced_preflight_credential_can_be_ready`
8. `commitmentless_preflight_possession_can_be_ready`

`delegated/fstar.log` ends with `All verification conditions discharged successfully`.

## What the kernel decides

`plan_enrollment_preflight` receives a `grant: Option<EnrollmentGrantFacts>`
and an explicit three-state account observation
(`NotQueried`/`Absent`/`Present(EnrollmentAccountFacts)`). It returns
`ReadyToConsume { epoch, possession }` or the first rejection in the handler's
historical status/message precedence:

1. `GrantUnavailable` -> 401 (`recovery grant expired or already used`)
2. `AccountUnavailable` -> fail-closed internal (unreachable through the
   production wiring; an unknown is never treated as observed absence)
3. `AccountAbsent` -> 404 (`account no longer exists`)
4. `EpochMismatch` -> 401 (`... vault key rotation`)
5. `RotationPaused` -> 409 (`device enrollment is paused ...`)
6. `CommitmentMissing` -> 401 (`... recovery setup deletion or rotation`)
7. `CredentialReplaced` -> 401 (`... credential replacement`)

The handler deliberately passes `NotQueried` when the non-consuming grant
lookup misses, so the 401 precedes any account query (privacy). Key decoding
and length validation still precede the grant lookup and return 400. The
permit is only permission to attempt the atomic `get_del`; it does not claim
consumption and does not authorize insertion. After `get_del`, the handler
requires the removed grant to equal both the pre-observation and the
preflight permit's epoch/possession. `plan_enrollment` then builds the final
`EnrollmentPermit` from the actual consumed/matching grant, the live row
observations and decoded key lengths. Terminal policy denial leaves the grant
consumed; retryable storage/rotation paths restore it as before.

## Tests

Run under `~/.local/opt/vela-tools/bin/vela-heavy` (global lock, 3 GiB, no swap,
one worker), pinned hax 0.3.7 / F★ 2025.10.06 / Z3 4.13.3, with the warm parent
`t3-700776df/target` reused through `CARGO_TARGET_DIR`:

- `delegated/fstar.log`: fresh extraction and full F★ check (79/79).
- `delegated/policy-tests.log`: 7 unit tests + 8 observation-enumeration tests.
- `delegated/integration-tests.log`: 63/63 server integration tests.
- `delegated/server-lib-tests.log`: 57/57 server library tests.
- `delegated/lifecycle-model-tests.log`: 3/3 bounded M14 checks.

New integration coverage:

- `enroll_device_missing_grant_returns_401_before_account_state`: a missing
  grant returns 401 even when the account is rotating, exercising the historical error precedence. The absence of an account
  query is confirmed by code inspection, not proved by the HTTP assertion.
- `enroll_device_validates_keys_before_the_grant_lookup_and_consumption`:
  400 before grant lookup, 400 preserves the grant, corrected retry consumes it.
- `recovery_enrollment_grant_is_invalid_after_key_rotation`: now also asserts
  the pre-consumption epoch rejection leaves the grant stored.
- `replacing_a_recovery_credential_blocks_a_grant_without_consuming_it`:
  rejection leaves the grant stored, and restoring the old credential revives
  the same grant within TTL.
- `possession_grant_requires_a_staged_commitment_but_restaging_revives_it`:
  missing commitment rejects without consuming; re-staging a *different*
  non-empty commitment revives the same grant.

The policy enumeration exercises the full grant/account/epoch/rotation/
credential/commitment grid. Its oracle mirrors the implementation's ordering;
it is a regression, not an independent formal specification. The checked
plan postcondition refines that shared rejection predicate. A separate proof
against independently stated ordering is still required. The post-insert race
recheck historically prioritizes authority revocation before rotation, unlike
preflight; those concurrent effects remain outside this kernel.

## Remaining correspondence and limits

- At delegated-run time the parent inventory was 212/219 and recovery 71.
  Parent integration updates it to 220 postconditions / 227 selections and
  recovery 79. Hosted reproduction of this increment remains pending.
- The kernel proves conditional decisions and permit construction, not the
  handler's SQL/store effects, the atomic `get_del`, the guarded insert, or the
  mapping from status/message to HTTP. Those remain inspected glue.
- The stored grant embeds no user id, commitment digest/generation or split id.
  `user_matches` is the `(user_id, grant)` store-key binding, not an independent
  identity comparison.
- Early credential/commitment rejection runs before consumption. The same grant
  can therefore be redeemed within TTL if the old credential is restored or any
  non-empty commitment is restaged. This is characterized by tests; it is not a
  proof of permanent revocation or exact commitment binding. Stronger behavior
  needs the grant value bound to user id, commitment digest and split/epoch
  generation, with revocation consuming the grant or bumping a revocation
  generation.
- Observation origins (SQL row decoding, sled operations, base64/serde, UUIDs,
  clocks, WebAuthn/proof verifiers, rate limits) remain trusted.
- No full handler/I/O, native, protocol or whole-system theorem is claimed.

## Parent reproduction

`parent-fstar.log` records fresh extraction and full checking in the parent
`t3-700776df` checkout after integration as `5361406`. The generated extraction is
byte-identical to the archived artifact (SHA-256 above): 79 contracts,
7 unit and 8 observation tests. Warnings originate in the pinned imported
hax library; all selected module verification conditions are discharged.
The command used pinned hax/F★ paths and `CARGO_HOME=/tmp/vela-hax-cargo`
through `vela-heavy serverVELA/vela-recovery-policy/verify-fstar.sh`.

The parent also defers stored-commitment decoding when epoch or rotation
already rejects, preserving the historical error precedence for malformed
stored bytes. The unused commitment length is zero in those already-rejected
cases, not a claim that a decode observed absence; a staged/explicit-unknown
interface remains a correspondence improvement. The targeted epoch regression now stores invalid base64 and
checks that rejection remains 401 for epoch mismatch, with the grant intact.

`parent-epoch-precedence.log` records the malformed stored-commitment / stale
epoch regression (1 passed). `parent-review-cases.log` records a new HTTP
scenario table (1 passed) covering malformed request keys before missing-grant
lookup, a stored grant for a missing account (404), and rotation combined with
credential replacement and malformed commitment storage (409, grant intact).
The test inventory is now 64 integration tests; the delegated full-suite run
was the preceding 63-test snapshot. The parent ran these two targeted tests,
not a second full integration suite. `parent-sources.txt` pins the integrated
sources; formatting-only changes do not alter these scenarios.

Internal review found no well-formed-path authorization bypass. Its remaining
ordering-specification concern and the historical post-insert race priority
are documented above and in the global preflight note. This review did not
independently run the proof tools and is not an external audit.

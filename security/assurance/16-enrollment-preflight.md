# Recovery enrollment preflight sequencing

Recovery now has 79 selected functions with 79 postconditions; the extracted
Rust corpus has 220 postconditions over 227 selections. Eight new contracts
cover preflight decision construction and missing/unknown/invalid observations.
This is a scoped implementation increment, not a full handler/I/O theorem.

Previously, unverified handler early returns checked every enrollment
conjunct before calling the policy. The final checked decision confirmed facts
that the caller already accepted. The production handler now obtains the
account/epoch/rotation/credential/commitment rejection reason from
`plan_enrollment_preflight`. Its current postcondition relates the plan to
the same rejection predicate used by its implementation and checks permit
fields. The predicate's guard order is inspected and regression-tested; an
independent formal specification of that ordering remains an obligation.

| Observation | Preflight result |
|---|---|
| No grant | Grant unavailable; account query is skipped |
| Grant but account not queried | Fail closed as unknown, distinct from absent |
| Query finds no account | Account absent |
| Grant/live epoch differs | Epoch mismatch |
| Rotation column set | Rotation paused |
| Possession grant with empty/missing commitment | Commitment missing |
| Credential grant with replaced credential | Credential replaced |
| All applicable guards hold | `ReadyToConsume` with the observed epoch/type |

Key decoding and length validation still occur before grant lookup. Account
observation is conditional on successful non-consuming grant lookup. Commitment
decoding is deferred when an epoch/rotation guard already rejects, preserving
historical precedence even for malformed stored commitment bytes. In those
already-rejected cases the handler supplies zero as an unused length placeholder;
it has not observed commitment absence. The preflight rejects on the preceding
guard regardless of that value. This is a conditional decision argument, not
an exact observation-origin theorem; a staged or explicit-unknown commitment
interface would make that distinction structural. Those origins
and the conditional SQL execution remain inspected glue, not checked traces.

`ReadyToConsume` authorizes only attempting the atomic store `get_del`. It
asserts neither successful consumption nor permission to insert a device. The
handler compares the removed grant with the full observed grant and the
preflight permit's epoch/type, then obtains its final enrollment permit from
the actual consumption observations. The guarded SQL insert remains the
concurrent authority check. After an insert race, the historical recheck
prioritizes credential/commitment revocation before the rotation conflict;
this differs from preflight when both change concurrently. That race ordering
and its interleavings are not covered by the preflight theorem. Terminal policy denial leaves a grant consumed;
existing retryable storage/rotation paths restore it. Their effects, atomicity
and crash behavior remain unproved.

The grant carries no embedded user id, commitment digest/generation or split
identifier. User binding is conditional on the request/store key. Rejecting
before consumption leaves a grant available within its TTL: restoring the old
credential or staging any non-empty possession commitment can make it usable
again. Tests characterize these cases; permanent revocation and exact
commitment binding are not proved or implemented by this increment.

[Evidence](proof-logs/current/recovery-enrollment-preflight/README.md) records
fresh extraction/F★ checks and concrete tests, separated by worktree. SQL row
decoding, grant serialization, UUIDs, clocks/TTL, verifier results and store
semantics remain trusted inputs. No Tamarin/Rust composition, native refinement
or whole-system theorem follows from these contracts.

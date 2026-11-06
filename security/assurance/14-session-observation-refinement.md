# 14. Web-session observation refinement

This increment verifies the Rust constructors used by web-session grant and
RW token-exchange handlers. It adds ten checked postconditions; the session
crate now has 19 postconditions over 21 directly selected functions, and the
corpus reached 183 postconditions / 190 directly selected functions at this
increment. The [later recovery increment](15-recovery-possession-enrollment.md)
extends the inventory further. Hosted
reproduction of this increment is pending. The preceding 173-postcondition
corpus passed on `5fa4e9f`.

| Observed value | Checked construction |
|---|---|
| Expected approver `Option<u128>` and authenticated user `u128` | Grant binding requires a present, equal expected account; absence rejects |
| Nonce length and comparison result | Grant nonce fact requires exactly 32 bytes and successful comparison |
| Phase, mode, key presence, declared epoch | Preserved exactly into grant facts |
| Granted account and committed approver, both optional IDs | Token binding requires two present, equal IDs; absent/absent never matches |
| Stored nonce presence | Preserved as the token's nonce-binding observation |
| Actual atomic challenge-take result | Its presence becomes the consumed-challenge observation |
| Actual signature verifier result | Its success becomes the signature-valid observation |

`plan_observed_grant` and `plan_observed_web_token` compose these constructors
with the existing verified policies. The resulting permits retain the existing
mode, epoch, scope, expiry and hard-cap contracts. Production code converts
parsed UUIDs through `as_u128` and passes the observations to these entry points.
It preserves the existing early returns and error precedence. The former literal
`signature_valid: true` is now computed from the verifier's `Result` before its
existing error branch.

Six universally checked rejection theorems cover missing approver, invalid
nonce length, cross-account exchange, absent accounts, unconsumed challenge
and failed signature observations. Fresh extraction/F★ checking passed with
zero local `assume val`; eight policy tests and thirteen existing HTTP/store/
database integration tests passed. The latter cover wrong nonce/account,
stale epoch, scope restrictions, token renewal and budgets, vault access and
an epoch-commit interleaving. Exact extraction and raw logs are retained in
[the local evidence](proof-logs/current/session-observation-refinement/README.md).

The contracts establish construction and policy composition **for supplied
observations**. They do not prove SQL row origins, UUID parsing/conversion,
status/mode decoding, constant-time nonce comparison, verifier correctness,
clock readings, sled atomicity, SQL execution, signing or JTI tracking.
`nonce_present` records the stored grant context; it is not a new proof of the
grant's history. Paths returning before construction remain unverified glue.
Full request/database traces, revocation races, malicious-server behavior,
client/FFI semantics and cross-protocol composition remain open obligations.

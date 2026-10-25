# Login byte producer and nonce composition

This increment advances implementation correspondence under the selected
OS/compiler and primitive-security trust boundary. It does not establish a
whole-system theorem or an external audit.

## Pure byte path

The extracted production `stored_tag_from_bytes` preserves the real slice
length and copies the first min(length, 9) bytes exactly, padding with zero.
The producer theorem composes this actual function with the actual classifier:
acceptance is equivalent to the raw slice being the expected literal `login`,
`enroll` or `web_token`. A separate theorem covers the actual
`purpose_tag_bytes` issuer → convert → classify path. The specification uses
independent raw-slice byte predicates and reuses the bounded-classifier proof.
The extracted postcondition is checked against the implementation; some
subsequent lemmas use that checked contract.

Slices are hax sequences bounded by the modeled `max_usize`. Slice/array,
integer, imported models, extraction and proof tools remain trusted. There is
no proof of store/write/take round trips, TTL, Vec/as_deref/Option glue or
literal-pointer provenance. The three new Rust tests cover four scenarios:
lengths, long values, corruption and truncation. Mutating retained length with
a weakened contract fails `producer_len_usize`; corrupting a copied byte
fails the extracted constructor's postcondition.

## Concurrent login interface

The composition executes the actual extracted login step across any finite
number of requests and an arbitrarily long interleaved schedule. A modeled
atomic take removes the one present nonce and supplies its purpose decision.
Successful admission consumes that nonce. Failed takes leave it present and
end that request. The unbounded induction proves at most one accepted request,
one Respond effect and one successful issuance observation per nonce. Absent
and non-login initial nonces never admit a login. Success, contention,
wrong-purpose spend, missing nonce and failure witnesses establish reachability.
Two mutation checks reject a reusable nonce and non-login acceptance.

This is conditional on one nonce key, a purpose-correct linearizable take,
paired effects/observations and faithful handler execution. The purpose is an
abstract Login/Other value, not raw bytes. The pure byte result and concurrent
module are checked separately: their bridge through the actual store is not
proved. Token/JTI effects, SQL rows, verification, revocation linearization,
crash/retry behavior, nonce re-issuance, cross-endpoint and multi-node lifecycle
composition remain outside this theorem.

## Inventory and reproduction

The focused extraction selects 16 functions with 12 explicit postconditions
(3 challenge/producer, 9 login; 8 transition contracts require sound state).
The producer adds 23 handwritten lemmas; composition adds 60. The unchanged
base inventory remains 249 postconditions / 256 selections across 14 artifacts;
focused artifacts are counted separately. Historical session extraction is
unchanged at 19 postconditions / 21 selections.

`serverVELA/vela-session-policy/verify-fstar.sh` freshly extracts/checks the
historical module, then checks producer, trace and composition in one focused
invocation. It does not repeat extraction to run the composition. The standalone
`verify-fstar-login-composition.sh` checks existing focused artifacts without
regeneration, for targeted reproduction only. Both use the shared source guard.
Local heavy commands are serialized under the 3 GiB/no-swap/one-worker cap.

The [integrated parent replay](proof-logs/current/login-integrated-proofs/README.md)
checks all six focused modules together after fresh extraction.

Original evidence: [producer](proof-logs/current/login-tag-producer/README.md),
[composition](proof-logs/current/login-nonce-composition/README.md). These retain
their original source snapshots and worktree provenance. Hosted green `5ae87da`
predates both additions. Actual store/handler refinement and joint whole-system
composition remain open regardless of the local verdicts.

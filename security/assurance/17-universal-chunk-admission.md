# Universal sync chunk-admission predicate

The existing extracted `plan_chunk_download` is now checked against a separately
stated predicate in twenty handwritten F★ lemmas. This is a supplemental kernel
proof, not twenty new Rust postconditions: the Rust corpus remains 245 explicit
postconditions over 252 selected functions, and its historical eleven-contract
sync artifact is byte-identical.

For arbitrary facts and a permit, the actual planner returns `Accept(permit)`
exactly when both caller-supplied flags hold, the server clock is positive,
the optional recorded baseline is no greater than that clock, and the permit
contains exactly that clock. The proof additionally checks rejection, permit
uniqueness, arbitrary baseline bounds, equal-clock redelivery and concrete
accept/reject instances. Signed clock extremes are checked; raw epoch integers
are not fields of this API. `None` means no recorded baseline; `Some(0)` is a
distinct observation but produces the same decisions because clocks must be
at least one. A negative baseline cannot admit a nonpositive clock.

The predicate is stated over raw integers/options instead of calling the
implementation's authorization predicate. Agreement with that specification
is universally checked. The selection of the specification and interpretation
of its input flags remain review obligations; syntax independence is not a
proof of security requirements or observation origins.

The module proves neither that ciphertext opening established the AAD flag nor
that an integer epoch established the epoch flag. The permit has only a clock.
Context/account/server binding, authenticated-open composition, baseline
persistence and native/desktop callers remain outside this theorem. A caller
providing an incorrect flag is not made safe by a correct policy kernel.
The unmerged mobile-runtime and focused integer-epoch work is separate.

`verify-fstar.sh` regenerates the historical extraction and then calls the new
lemma verifier separately, using only that extraction directory. A focused
module with the same F★ name cannot shadow it. Supplied modules are checked
with caching disabled; imported proof libraries remain trusted. Exact module,
count/name and source-escape guards detect drift, not semantic adequacy.

[Evidence](proof-logs/current/f5-universal-chunk-admission/README.md) separates
the delegated mobile-dependent snapshot from the standalone parent result.
The parent check passes eleven existing contracts, twenty handwritten lemmas,
five Rust tests and six source-guard tests. Hosted reproduction of the added
lemma gate is pending. No full-system or external-audit claim follows.

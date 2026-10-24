# Sync policy and universal chunk-admission proof

`verify-fstar.sh` freshly extracts and checks the historical 11 Rust
postconditions, then invokes `verify-fstar-chunk.sh` in a separate F★ process.
The second invocation checks 20 handwritten lemmas against that same extracted
`plan_chunk_download`, with caching disabled for the supplied modules.

For every input and permit, `Accept(permit)` is equivalent to:

- the caller-supplied AAD and epoch-positivity flags hold;
- the server clock is at least 1;
- the baseline is absent, or the server clock is at least that baseline;
- the permit carries exactly the server clock.

The module separately states this predicate over raw clocks/options. It also
checks rejection, permit uniqueness, arbitrary baseline floors, equal-clock
redelivery, signed-clock extremes and concrete accept/reject witnesses.
`None` and `Some(0)` produce the same decisions because clocks must be positive;
they remain distinct observations. Negative baselines do not bypass the
positive-clock requirement. A false epoch flag rejects even the largest clock.
The permit contains a clock, not an integer epoch.

These are conditional kernel properties. This module neither derives the AAD
flag from ciphertext nor the epoch flag from an integer. It does not prove
chunk/account/server context binding, actual authenticated opening, baseline
storage, native/desktop callers or whole-system rollback protection. In
particular, a caller supplying an incorrect flag remains outside this theorem.
The mobile runtime and focused integer-epoch kernel are separate work awaiting
integration. Production Rust decisions are unchanged by this increment.

Run through `vela-heavy` with pinned hax 0.3.7, F★ 2025.10.06 and Z3 4.13.3;
see the client-recovery policy README for tool setup. The verifier logs version,
module hashes and argv. Its source/count guard rejects local proof escapes and
source options (allowing only exact hax-generated fuel/budget boilerplate);
the guard is not a soundness certificate. Imported models, extraction and
proof tools remain trusted. The 20 handwritten lemmas add zero Rust
postconditions to the 245-contract corpus. Evidence and run provenance are in
`security/assurance/proof-logs/current/f5-universal-chunk-admission/`.

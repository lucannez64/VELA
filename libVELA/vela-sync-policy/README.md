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
The integrated mobile path uses the separate integer-epoch kernel described
below; relating its byte/FFI/storage observations to these pure inputs remains
unproved. The universal chunk-lemma increment itself changes no production
Rust decision.

Run through `vela-heavy` with pinned hax 0.3.7, F★ 2025.10.06 and Z3 4.13.3;
see the client-recovery policy README for tool setup. The verifier logs version,
module hashes and argv. Its source/count guard rejects local proof escapes and
source options (allowing only exact hax-generated fuel/budget boilerplate);
the guard is not a soundness certificate. Imported models, extraction and
proof tools remain trusted. The 20 handwritten lemmas add zero Rust
postconditions to the global Rust contract census. Evidence and run provenance are in
`security/assurance/proof-logs/current/f5-universal-chunk-admission/`.

## Integer-epoch kernel and mobile callers

The local runtime candidate includes the token-header, missing-pin and
RMS-snapshot corrections and passed focused internal review and awaits hosted validation.
The kernel proofs do not establish those implementation traces.


A focused extraction checks four additional Rust postconditions for
`plan_sync_epoch_match` and its witnesses. Six handwritten lemmas characterize
acceptance exactly as equality of two positive integer inputs. It is verified
in its own F★ invocation because its module name matches the historical
extraction; the include directories are kept separate. Combined inventory:
15 extracted Rust postconditions, 6 epoch lemmas and 20 chunk lemmas. Only the
four extracted contracts increase the global Rust census (245 → 249).

Production Android/Apple downloads call the Rust admitted-open entry point:
compare supplied integer epochs, require a sealed envelope, perform the actual
AEAD open, then apply the chunk policy and return its admitted clock. Epoch-1
seals bind chunk id/clock; later epochs additionally bind epoch. Kotlin/Swift
record the returned clock after the decode/merge/persistence path. Namespaced
floors use server/account/epoch context. Android pins its account id across
automatic re-authentication and publishes settings under its commit lock.
These are implemented and tested paths, not an end-to-end refinement theorem.

Legacy unsealed or clock-zero chunks fail closed. A distinct migration error
is surfaced, but a trusted migration/re-sealing workflow is not implemented.
Old un-namespaced floors are not migrated; the first post-upgrade sync has an
explicit first-contact replay window. Sign-out/reset clears all contexts under
the current one-account-per-install assumption.

Android saves via temp-file data sync and same-directory atomic replacement;
the parent directory is not synced, so abrupt-power-loss persistence of the
rename is not ensured here. Vault and baseline writes are not one transaction:
a crash can lose an unrecorded baseline advance and leave a replay window;
this does not establish a one-revision or once-only bound. Successful preferences
commit durability and filesystem effects are trusted interfaces, not proved.

The iOS NSLock serializes a single syncing writer process only. A second
process's stale whole-map write could lower floors and erase other contexts;
there is no cross-process guarantee. Swift compilation/tests remain pending
on this Linux host. JNI/C/JSON glue, OS storage, origin of AAD/epoch facts,
`server_epoch_is_next` on adoption and complete client traces remain open.

# Integrated raw-byte/world bridge replay and literal refusal

The parent aggregate verifier freshly checks the historical artifact,
regenerates the focused extraction and verifies all seven focused modules
in one F* invocation. `full-verify.log` ends with all VCs discharged. The
shared source guard checks 2 extracted + 5 handwritten proof modules.
The run uses hax 0.3.7, nightly-2025-11-08, F* 2025.10.06, Z3 4.13.3 and
`--cache_off`, serialized under the 3 GiB/no-swap/one-worker cap. Imported
models emit the retained warnings; zero warnings are not claimed.

18 crate unit + 13 driver tests pass; repeated warm test runs are not counted
as new coverage. This increment adds no Rust/handler code, so no server test
rerun is attributed to it. The historical artifact remains 19 postconditions /
21 selections and focused extraction 12 / 16 (8 conditional). The base census
is unchanged at 249 postconditions / 256 selections / 14 artifacts. The new
raw-world bridge adds 40 handwritten lemmas, giving 164 across the five proof
modules; these are not Rust contracts.

The projection connects modeled raw-slice takes through the actual extracted
converter and classifier to the abstract nonce world for every action and
arbitrary schedules. It transfers the at-most-one accepted request, Respond
effect and successful token-issue observation bounds. Literal meaning comes
from the checked producer proof. It does not prove that actual Store results
or handler Option/Vec glue supply those modeled bytes, get_del linearizability,
effect/observation pairing, SQL/verifier/JTI/PASETO/TTL/crash semantics, or
whole-system composition. This is local replay, not a hosted result or audit.
Original delegated evidence retains its original 1902ecd input snapshot.

## Post-review general literal refusal

`literal-refusal.log` is the subsequent seven-module replay after adding four
lemmas. All VCs discharge; the raw module now has **44** lemmas and the five
handwritten modules total **168**. The original aggregate log above checked
the 40-lemma snapshot; `source-hashes.txt` now pins the final proof inputs.
`raw_non_literal_never_admits` uses the independently stated literal predicate
and its checked equivalence to the actual classifier for every optional value
and schedule. `raw_admission_requires_literal_login` makes literal login bytes
necessary for admission, Respond effects or successful issuance observations.
The success witness instantiates this necessity, and `raw_run_invariant`
exposes the full transported invariant. The at-most-one count theorem remains
purpose-agnostic; mutation B originally rejects the literal bridge/refusal
witnesses, not that bound.

The standalone runner also now uses `cargo metadata --locked` and hashes
Cargo.toml and the workspace lockfile among its input guards. This later
reproduction hardening leaves F* inputs/argv unchanged; `locked-metadata.log`
records a separate successful metadata check. It is not attributed to the
original script invocation. Real store/handler and physical trust boundaries
remain open.

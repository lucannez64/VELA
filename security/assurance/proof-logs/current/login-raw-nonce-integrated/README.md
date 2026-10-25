# Integrated raw-byte/world bridge replay

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

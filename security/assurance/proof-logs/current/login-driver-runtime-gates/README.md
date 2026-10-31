# Integrated login runtime gates

The original login proof/evidence was authored on `c8a377d`, committed as
`3885e17`, and cherry-picked onto the green `d98475f` parent as `40129b6`.
Its static internal review found that six handler decisions only asserted
expected driver effects in debug builds. The handler now checks every effect
at runtime, including the initial `ConsumeChallenge` and final `Respond`.
Unexpected effects fail closed. Exact failure categories must match the real
operation's result before its original error is returned. SQL, decoding,
verifier and storage origins, and handler execution remain reviewed glue.

The correction changes no pure policy or F* theorem. It adds zero Rust
postconditions and does not claim a whole-handler refinement theorem.
The original focused proof selects 12 production functions (3 challenge +
9 login), with 11 explicit postconditions, 8 carrying the sound-state
precondition. `purpose_stored_tag` has no explicit postcondition. The original
runner's concluding “11 / 3 + 8” is a reporting error, not the artifact count.
Historical session extraction remains 21 selections / 19 postconditions.

## Fresh integrated validation

`server-tests.log` records 3 challenge model tests, 68 HTTP integration tests
and 5 focused login handler tests, all passing. The fifth handler test seeds
a corrupt nonce key with a valid login tag and checks that decode returns
400 after consumption, before either failure counter is recorded. The
one-nonce handler test now uses a two-worker Tokio runtime; `tokio::join!`
interleaves two requests, without controlling a specific scheduler race.
The existing separate real-store concurrent test remains in the challenge
model suite. Finite concurrency tests do not establish linearizability.

`source-policy-tests.log` records all 49 Python source/shape regression tests.
Workflow syntax passes actionlint 1.7.12. CI now invokes the new handler and
policy test targets, runs the executable focused proof script through the
session verifier, and retains focused extractions/lemmas as artifacts.
No hax/F* rerun is attributed to this runtime-only correction; the unchanged
proof sources retain their original delegated evidence.

The byte-to-bounded-tag producer and issuer are still tested Rust glue in this
snapshot. Concurrent one-nonce F* composition is also open. Separate active
work on those obligations is excluded from this evidence. Cryptography,
SQL/store semantics, effect fidelity, observation origins, revocation and
issuance linearization, crashes and whole-system composition remain unproved.
This is an internal review and local run, not an external audit or hosted result.

## Git executable-mode correction

The follow-up review found that `core.fileMode=false` prevented the prior
`chmod` from entering Git's index. The script remained 100644 in `6a97e8f`.
`git update-index --chmod=+x` now explicitly records 100755. The regression
checks the indexed mode of every focused driver runner, rather than relying on
local filesystem permissions. `mode-before.log` shows the new check failing
on 100644; `mode-after.log` records all **50** Python checks passing after the
index fix. This supersedes the earlier claim that 3aaac25 had committed the
executable permission. Proof source content and theorem counts are unchanged.

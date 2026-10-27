# Evidence index

The [hosted baseline on 350cd57](hosted-350cd57/README.md) passed all security
jobs, including 212 F★ postconditions, seven computational games and the
instrumented journal gate. It predates the handwritten journal encoding and
preflight/ordering increments. The [hosted baseline on 368bcc0](hosted-368bcc0/README.md) reproduces the
231-postcondition / 238-function snapshot and the journal encoding check.

The published sharing correction has 245 postconditions / 252 selected functions;
the local mobile candidate adds four, giving 249 / 256. Runtime publication
passed focused internal review and hosted validation on fdee2bc.
The [sharing arithmetic correction](share-inbox-arithmetic/README.md) checks
the fourteen new sharing contracts after fixing a universal i64 overflow
obligation. Hosted reproduction of that correction passed in the [5d8c366 snapshot](hosted-5d8c366/README.md).

The [25bf944 hosted snapshot](hosted-25bf944/README.md) passed all 15 checks,
including the universal chunk-admission lemmas with the 245-contract census.
The newer local mobile/journal candidate is not part of that hosted result.

The [fdee2bc hosted baseline](hosted-fdee2bc/README.md) covers the mobile/epoch
and stronger encoded journal increments, with all fifteen checks passing.
The later [recovery-redemption driver](recovery-redemption-driver/README.md) passed hosted CI on aaf708f (all fifteen checks).
Its [concurrent composition](recovery-redemption-composition/README.md) passed hosted CI on edaee5a.

Current login-boundary work:

- [Durable token admission](login-revocation-admission/README.md): closes a
  reproduced late-login/sentinel-expiry gap, makes repeat revocation retry token
  cleanup, and suppresses undelivered renewal on logout/schema/revoke. Tested
  implementation behavior, not an unbounded middleware theorem.
- [Driver source policy](driver-source-policy/README.md): lexer-aware escape and
  local-include inventory gates with twelve regression tests. This is not a
  replacement for F* or a semantic correspondence certificate.

Recent increments (see the hosted baseline above for snapshot coverage):

- [Web-session observations](session-observation-refinement/README.md): ten
  additional checked postconditions (183 at that snapshot), exact extraction,
  eight policy tests and thirteen handler integration tests.
- [Possession/enrollment observations](recovery-possession-enrollment/README.md):
  29 additional contracts, taking recovery to 71, with decoded key lengths
  derived in the checked constructor and concrete handler regressions.
- [Enrollment preflight](recovery-enrollment-preflight/README.md): eight
  additional contracts route live pre-consumption decisions through the policy;
  eleven independent ordering/readiness contracts follow, taking recovery to 90.
- [Nonuniform GDH companion](x25519-nonuniform-gdh/README.md): the seventh
  computational game; six positive proofs plus the explicit legacy nonproof,
  with full per-model logs. Collision/distribution and Rust correspondence
  assumptions are documented; an internal review is not an external audit.

- [Universal chunk admission](f5-universal-chunk-admission/README.md): twenty
  handwritten lemmas over the historical eleven-contract extraction, integrated
  independently of mobile runtime changes. Rust contract counts are unchanged.

- [Encoded journal goals](journal-encoded-goals/README.md): all-pairs pin and
  generation properties, a concrete unary order and two-commit core/lift
  witness, freshly checked locally. Tamarin source embeddings remain open.

Other recent scoped evidence:

- [Journal all-pairs](journal-all-pairs/README.md): ten M28 and eleven M29
  results; the Tamarin source bridge remains manual.
- [Journal encoding equivalence](journal-encoding-equivalence/README.md): fresh
  pinned F★ lifting/projection check for typed single-slot encodings; no
  source equivalence or Rust refinement claim.
- [P-256 advisory repair](p256-advisory-fix/README.md): compatibility tests,
  dependency checks, and the local/hosted distinction.
- [Recovery constructors](recovery-fact-refinement/README.md): the preceding
  42-contract recovery snapshot and real-store insertion regression.

The snapshots below retain their original counts and provenance. They do not
by themselves establish results for later source changes or a whole-system
theorem. The manifest covers the current retained files.

# Archived local snapshot, 2026-10-23

Implementation HEAD: `148ff3261b62bd60df0d99d354e093500779fdce`, with the
model/documentation/runner changes in the manifest's working tree. These are
maintainer-side local runs, not a successful new GitHub Actions run or an
independent audit.

- `full-run/summary.txt`: all default assurance steps passed. This includes
  35 Tamarin theories: 276 verified lemmas and five named intentional
  falsifications; the three expected ProVerif verdicts; and four passing
  ORAM statistical tests. `full-run/versions.txt` records actual tool/compiler
  versions, start time, HEAD and dirty-path count. The compiler here is the
  host's nightly, whereas new security CI selects Rust 1.99.1.
- `m13b_*.log`, `m19c_*.log`, `m27_*.log`: full proof output for the five new
  network-boundary theories (17 verified lemmas), including proof trees and
  expected attack witnesses against the old designs. The final focused rerun
  strengthens share secrecy to require revelation of the exact recipient
  key before attacker knowledge, and strengthens revision monotonicity to
  cover every earlier admission in the same slot. This rerun supersedes the earlier M19c
  output under `full-run/network/`.
- `credential-release.log` and `credential-release/*.out`: focused run after
  fixing the SiteMode / Escaped event-versus-persistent-fact name conflicts
  in M9a, M9c and M10. Exactly 83 verified / five intended falsifications,
  with no warnings. The focused gate additionally checks named verdicts.
- `crypto-tests.log`: 121 core Rust unit tests passed. Command:
  `security/assurance/bounded.sh env CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm cargo +nightly test --manifest-path libVELA/vela-crypto/Cargo.toml --locked --lib`.
- `client-share-policy-tests.log`: three unit tests and two bounded fact-space
  tests passed, plus zero doc tests. This is executable evidence, not an F*
  proof. Command: the same bounded Cargo invocation with manifest
  `libVELA/vela-client-share-policy/Cargo.toml` and without `--lib`.
- `hax-install-failed.log`: earlier **failed** names-helper build. The custom
  driver could not find a code-generation backend because of compiler profile
  configuration. This failure was resolved by explicitly selecting LLVM.
- `hax-helper-install.log`: successful names-helper installation with isolated
  Cargo home, `RUSTFLAGS="--cfg hax"`, and
  `CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm`.
- `hax-engine-install-capped.log`, `hax-engine-gc-capped.log`, and
  `hax-bytecode-capped.log`: subsequent engine attempts, all stopped at the
  **3 GiB** cap. Tighter OCaml GC got past the first large native module, but
  later compilation still exceeded the cap. A bytecode-only build also hit
  the cap. The bytecode experiment changed only `(modes byte)` in the
  upstream `engine/bin/dune` executable stanza; that change was reverted.
  These are failures, not extraction or proof results.
- `hax-engine-memory-limit.txt` and `resource-limits.txt`: systemd scope
  records confirming `oom-kill` results at 3G memory peaks. No larger local
  allocation was attempted in those failed runs. The later successful run
  below used a larger cap with user authorization.
- `hax-engine-install-success.log` and `hax-engine-install-resources.txt`:
  successful native engine build, about 11 minutes, with cap increased from
  5 to 6 GiB and observed peak about 4.8 GiB. The final exact metric command
  failed because it parsed hybrid cgroups incorrectly; journal and live
  observation provide the memory evidence. Installed dependencies were reused.
- `refinement-5g/`: **all eight policy crates passed fresh extraction and F***
  without `--lax`. Logs, checked extractions, lockfiles, exact harness and
  resource measurements are retained. Each workflow had a 5 GiB cap, zero
  swap and one worker; peaks were 0.74–2.06 GiB. These supersede the earlier
  incomplete-proof status, but do not establish current CI success.
- `boundary-review/sharing-witnesses.log`: three passing diagnostic witnesses
  demonstrate unsafe current behavior, not security passes. The temporary patch
  and review are in `../../sharing-review-witness.patch` and
  `../../07-boundary-review.md`; production source was restored afterward.
- `boundary-review/crypto-tests.log`: separate crypto unit-test rerun after review.
- `sharing-fixes/`: full desktop-core unit suite after the BR-1–BR-3 fixes,
  including permanent regression tests that assert the safe behavior. Old
  `boundary-review/` witnesses are historical and do not describe fixed code.
- `extended-formalization/`: eleven additional checked production contracts
  (ten transaction/recovery, one actual fact constructor), seven M28 journal
  verdicts, the explicit String model, assumption inventory and regression runs.
  The stronger-goals unfinished log is explicitly not successful proof evidence.
- `trusted-boundary/`: current all-eight-policy checking after removing the
  eighteen local enum-equality assumptions; exact decoded-field/policy composition,
  prefix and AND-signature contracts; composed M29; fresh regression results.
  It supersedes earlier extraction snapshots for the current source and keeps
  the accepted trust boundary and remaining obligations explicit.
- `validation.txt`: workflow/shell syntax, local links, drift detection and
  negative checks for modified hashes, missing verdicts and timeouts.

The symbolic/test runs used a 3 GiB Linux cgroup cap without swap; Tamarin additionally
used one worker, a 1500 MiB GHC heap and a 180-second per-proof timeout.
`full-run/` preserves the existing runners' outputs: the old families print
count summaries and discard intermediate proof trees, while the new network
and credential runners retain their full proof outputs. No live current server exploit rerun is attached. Historical CI
logs in the parent directory remain identified by their older commit.

Reproduce with the commands in `../../04-reproducibility.md`. Logs contain
local absolute source paths; there are no deployment credentials in them.

The [login driver](login-driver/README.md) checks exact purpose recognition on
bounded stored tags and arbitrary per-request login event lists. Its
[runtime gate correction](login-driver-runtime-gates/README.md) enforces the
decisions in release builds, with fresh 3/68/5 server tests. The [raw-byte producer](login-tag-producer/README.md) and
[one-nonce composition](login-nonce-composition/README.md) now have separate
local proofs under their stated interfaces. Real store/handler correspondence
and the bridge between the raw-byte proof and purpose-bit composition remain
open; see [the scope note](../../19-login-producer-composition.md).

The [integrated login replay](login-integrated-proofs/README.md) records fresh
producer/trace/composition verification in one invocation, the unchanged
historical check, exact artifact hashes and 18 + 13 policy tests.

The [raw nonce bridge](login-raw-nonce-bridge/README.md) connects modeled
raw-slice takes through the production converter/classifier to the abstract
nonce world by per-action and arbitrary-schedule projection and general literal refusal (44 lemmas).
Real store/Option/Vec byte origins and handler fidelity remain outside it.

The [take adapter](challenge-take-adapter/README.md) proves the extracted
`Option<Vec<u8>>` challenge-take decision called by the handler equals an
independent literal-byte specification (26 lemmas, accept-absent mutant
rejected), replayed with all 8 focused modules on the current set.

The [revocation driver](revocation-driver/README.md) proves the revoke,
logout and revocation-admission decisions per request and under any
interleaving (13 contracts, 84 lemmas, three load-bearing mutations).

The [login](login-interpreter/README.md),
[revocation](revocation-interpreter/README.md),
[pairing](pairing-interpreter/README.md) and
[sharing](share-interpreter/README.md) interpreters extend the same check to
those handlers.

The [deletion interpreter](deletion-interpreter/README.md) checks the loop
`DELETE /account` runs: for every executor it performs exactly the driver's
effects, stops at the verdict and ends in a state the deletion theorems cover.

The [deletion driver](deletion-driver/README.md) proves the lockout-first,
fixed-order, commit-only-after-`users` deletion per request and no
cross-account deletion, second commit or locked-out admission under any
interleaving (11 contracts, 60 lemmas, three mutations).

The [vault upload driver](vault-upload-driver/README.md) proves the
`put_chunk`/`get_chunk` decisions per request and, against a modelled atomic
SQL guard, that no stale or unauthorized row is committed under any
interleaving with rotations (14 functions, 109 lemmas, seven load-bearing
mutations).

The [pairing driver](pairing-driver/README.md) proves package, claim,
completion and result decisions per request and under any interleaving (30
contracts, 110 lemmas, six load-bearing mutations) and fixed U-19.

The [WebAuthn recovery drivers](webauthn-recovery-driver/README.md) prove
registration, initiation and share release per request and under any
interleaving (27 contracts, 4 trace theorems, 47 composition lemmas, three
load-bearing mutations).

The [store world](challenge-store-world/README.md) joins the take adapter to
the raw nonce bridge: the login bounds hold over the store's actual
`Option<Vec<u8>>` result, with every take decided by the extracted adapter.

The [integrated raw-bridge replay](login-raw-nonce-integrated/README.md) records
fresh extraction and all seven focused modules verified together on the parent
source set, plus exact source hashes and 50 source-policy checks.

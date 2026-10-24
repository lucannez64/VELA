# Evidence index

The [hosted baseline on 350cd57](hosted-350cd57/README.md) passed all security
jobs, including 212 F★ postconditions, seven computational games and the
instrumented journal gate. It predates the handwritten journal encoding and
preflight/ordering increments. The current local corpus is 231 postconditions /
238 selected functions and still needs hosted reproduction.

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

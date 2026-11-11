# Received-byte signature transcript increment

Parent source snapshot: 275c3714838905661e2aecf17a417c266aa43031.
The last complete hosted baseline cited here remains e690dfc. This directory
records local evidence for the later increment; hosted reproduction is pending.
See [the exact mapping](../../../12-authenticated-transcript.md).

The fresh `fstar.log` records the share-policy dependency, crypto extraction,
share regressions, two negative privacy doctests and F★ checking. Both defined
String/Vec models are explicit checker inputs. The Vec extension's sequence,
length and prefix/suffix result refinements are checked definitions. They are
library-model refinements, separate from the 132 selected Rust postconditions.
Correspondence to Rust std remains trusted; allocation/termination is excluded.

The inventory is 139 directly selected functions / 132 explicit postconditions
in eleven Rust modules, plus two defined library models. Seven selected
specification/comparison functions have no explicit ensures. Zero local
assumption declarations and all-trivial selected Rust preconditions are
retained. No generated VELA function body was patched or replaced. Domain
concatenation and the parser use scoped fuel/ifuel 2, with solver limit 100.

The new checks add two contracts to the prior parser snapshot: exact body
slicing including rejection, and exact domain/body concatenation including
length bounds and rejection. The frame-parser result additionally retains the
exact signed body. Production sealing and opening use these helpers. Complete
primitive-wrapper, UTF-8/object, context and application/I/O refinement is open.
The eight policy modules are unchanged; this runner freshly checks the share
policy and all 24 crypto postconditions. The other seven policy proofs retain
their earlier evidence; their snapshots are copied here for inventory coherence.

Commands run from the repository root with the pinned tool paths activated
(hax 0.3.7, extraction Rust nightly-2025-11-08, official F★ 2025.10.06, Z3 4.13.3):

```bash
security/assurance/bounded.sh libVELA/vela-crypto/verify-share-facts-fstar.sh
security/assurance/bounded.sh cargo test --locked --manifest-path libVELA/vela-crypto/Cargo.toml --lib
security/assurance/bounded.sh cargo test --locked --manifest-path libVELA/vela-apple-bridge/Cargo.toml --lib
security/assurance/bounded.sh cargo test --locked --manifest-path libVELA/vela-android-bridge/Cargo.toml --lib
security/assurance/bounded.sh cargo test --locked --manifest-path desktopVELA/vela-desktop-core/Cargo.toml --lib
python3 security/assurance/check-proof-boundary.py
python3 security/formal/check-correspondence.py
python3 security/scan.py
```

All heavy commands ran sequentially with a 3 GiB process-tree cap, no swap and
one worker. These are x86_64 Linux extractions and host Rust tests, including
the bridge crates; they do not verify device/native execution. Normal tests used the local nightly and the explicit LLVM
codegen override. See [tool setup](../../../04-reproducibility.md) for pins and
activation. The original reference encoder still opens binary payloads, and
modified received payloads fail verification after valid recipient re-sealing.

`tool-versions.log` records the exact local test/compiler and proof-tool versions.
The extraction snapshots match source-tree outputs. Static boundary and
correspondence logs detect declaration/hash drift; they are not semantic
refinement proofs. Negative fixtures reject lax/admitted/unsafe proof flags.

Results: 130 crypto tests, 454 desktop tests (eight existing ignored),
15 Apple bridge tests and 25 Android bridge tests passed. The proof runner
also passed ten share-envelope regressions and two privacy compile-fail tests.
The Rust source scan reports zero findings.

The final explicit-model F★ command discharged every verification condition
in 89.136 seconds (tool-reported time); the enclosing runner exited zero.

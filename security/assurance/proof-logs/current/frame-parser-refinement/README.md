# Raw byte-frame and cursor refinement increment

Base: e690dfce2ea7fad8bad398387b306bbe5ee10f3a, whose complete hosted security
workflow passed. This directory records later local evidence, not a new hosted
result. See [the exact contract mapping](../../../11-parser-refinement.md).

fstar.log records a clean, successful execution of the current
`libVELA/vela-crypto/verify-share-facts-fstar.sh`, including extraction, share
regressions, two privacy compile-fail doctests and F★ checking. The current
corpus inventory is 137 directly selected functions / 130 explicit
postconditions (seven selected spec/comparison functions have no ensures).
Eight policy crates retain their previously checked, unchanged sources; this
run freshly checks the share policy dependency and all 22 crypto contracts.
The twelve extraction snapshots match the current source-tree outputs.

Eleven new postconditions extend the earlier 119-postcondition inventory:

- Exact LP and fixed-width integer splitting.
- Mutable LP/integer/prefix cursor effects, including unchanged state on failure.
- Atomic pair/four-field cursor readers and the complete frame parser's
  equivalence to a functional byte grammar, including rejection cases.
- Three opened-share accessor kernels preserving all header fields/item bytes.

No generated body was edited or replaced, no local assumption was added, and
all checked postconditions have trivial preconditions. The full frame function
uses scoped fuel/ifuel 2 for unfolding. Earlier monolithic searches exhausted
solver resources; grouped operations made the final proof compositional.
Imported models and the String view remain trusted. The static boundary gate
also rejects lax, admitted-SMT and unsafe-tactic execution flags; three negative
fixtures were checked. This lexical gate is not a logical proof checker.

All proof/build commands used the 3 GiB process-tree cap, no swap and one
worker, with hax 0.3.7, extraction Rust nightly-2025-11-08, official prebuilt
F★ 2025.10.06 and Z3 4.13.3. The final F★ check took about 84 seconds.
Normal Rust tests used the local nightly with LLVM explicitly selected.

Final regression evidence:

- crypto-tests.log: 128 passed.
- privacy-compile-fail.log: two negative API tests passed.
- apple-tests.log: 15 passed; android-tests.log: 25 passed.
- desktop-tests.log: 454 passed, zero failed, eight existing ignored.
- proof-boundary.log and correspondence.log: declaration/precondition inventory
  and reviewed source/model hashes pass; neither is semantic refinement.
- rust-scan.log: zero findings from the repository's Rust source scanner.

OpenedShare privacy is compiler enforcement for safe Rust. The read-only
methods delegate to the three checked kernels; complete wrapper/FFI/application
correspondence remains open. The concrete authenticated opener now calls the
checked byte parser, but UTF-8 conversion, crypto/recipient-key provenance,
encoder inverse, context origins, persistent effects and native caller behavior
still require their respective proofs. The complete system is not formalized.

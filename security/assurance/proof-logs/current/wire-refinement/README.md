# Fixed-width wire refinement and hosted CI repairs

Selected boundary: trusted OS/compiler and primitive security. Full-system
formalization remains incomplete.

`fstar.log` records fresh extraction and successful checking of the 19 share
policy contracts and all eleven crypto contracts. Five new Wire contracts
cover exact u64 big-endian decoding, quotient/remainder decomposition,
encoding round-trip, an explicit round-trip theorem and encoding injectivity.
The actual share-envelope writer/reader call the codec. No local assumption
was added. Across the existing policy corpus plus these kernels the inventory
is 122 selected functions / 119 explicit postconditions. Imported hax models,
the defined String view, extraction and proof tools remain trusted.

The runner is `libVELA/vela-crypto/verify-share-facts-fstar.sh`, inside
`security/assurance/bounded.sh`, using the pinned hax 0.3.7/F★ 2025.10.06/
Z3 4.13.3 toolchain. `--split_queries always` changes proof search only; all
obligations must succeed. The successful F★ command took about 62 seconds.
The three `.fst` snapshots are byte copies of that extraction. Earlier attempts
were stopped without completion: `interrupted-attempt.log` and
`direct-quotients-attempt.log` are diagnostic evidence, not proof results.

Local checks after integrating main 7d61d1e and updating ctutils to 0.4.4:

- `desktop-core-tests.log`: 454 passed, zero failed, eight existing ignored.
  Main moved import tests into the new vela-import crate, explaining the
  lower desktop count relative to earlier snapshots.
- `apple-bridge.log`: 15 passed; `android-bridge.log`: 25 passed.
- `wire-tests.log`: the final codec matches standard-library encoding on
  boundary cases and a fixed endian vector. Eight share-envelope tests also
  pass in the fresh proof runner.
- `crypto-tests-before-decomposition.log`: 123 passed with LLVM, before the
  encoder was refactored into checked byte steps. The final encoder is covered
  by the focused wire test, share tests and bridge tests above.
- The initial local all-crypto invocation hit a Cranelift compiler abort. It
  was rerun with `CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm`; this compiler failure
  is not a protocol failure or a successful verification result.
- `rust-scan.log`, `proof-boundary.log`, `correspondence.log`: passing source
  scan and drift gates. These gates are not refinement proofs.

See `hosted-ci.md` for the failed first hosted run and repairs. Hosted success
is still pending. The new signature reduction is a written argument for review,
not a machine-checked computational proof. Full parser, handler, native caller,
I/O and construction-composition obligations remain recorded in the status ledger.

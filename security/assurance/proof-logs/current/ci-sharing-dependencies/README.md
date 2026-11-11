# Stable sharing-job setup and Tokio advisory update

Failed hosted baseline: PR #175 at 9f0b3d3, security run
https://github.com/lucannez64/VELA/actions/runs/39972155636.

- sharing-boundaries (job 120477356895) failed before compilation because it
  set CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm on stable Cargo 1.99.1. Explicit
  backend selection requires an unstable feature. The stable job now uses its
  default LLVM backend; the nightly hax installer's feature opt-in is separate.
- static-scan (job 120477356865) reported RUSTSEC-2026-0386: Tokio AsyncFd
  constructors violate I/O safety. Server Tokio 1.52.3 and desktop/fuzz Tokio
  1.53.1 were updated to 1.53.3, inside the advisory's patched version range.
  No advisory exemption was added. Only the Tokio version/checksum blocks
  changed; dependency lists remain identical. See the
  [upstream change](https://github.com/tokio-rs/tokio/pull/8587).

Local validation:

- stable-backend-before.log reproduces the feature error on a dependency-free
  crate, from /tmp with a fresh CARGO_HOME. stable-backend-after.log records a
  successful stable build without the override. These are setup checks, not
  a completed run of the desktop suite on hosted CI.
- vela-ci3-deny-*.log record successful advisory, bans, licenses and sources
  checks for all five workspaces covered by CI: server, crypto, Android bridge,
  WASM bridge and core. These use cargo-deny 0.20.2, matching the failed CI run.
  Its release archive was verified against the GitHub release asset digest
  9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f.
- desktop-core-tests.log: 454 passed, zero failed, eight existing ignored.
- server-session-policy-tests.log: three finite session-policy tests pass.
- rekey-handler-conformance.log: the actual Axum/Turso conformance test passes
  all 24 upload orderings against the atomic commit guard.
- Review of these tests found an overstatement in the assurance table: session,
  enrollment and recovery model tests enumerate pure policy facts. They do not
  run HTTP handlers or database transitions. The table and CI step name now
  describe that boundary accurately; the rekey conformance test is separately
  identified as actual handler/database execution.
- Workflow YAML/run blocks parse; the Rust source scanner reports zero findings.
- Correspondence hashes were reviewed for the targeted lockfile update. The
  proof-boundary gate remains at 119 postconditions without local assume val
  declarations. No Rust/F★ proof bodies or model assumptions changed.

Tests/builds use the existing 3 GiB bounded runner with one worker. A successful
new hosted run is still required. These changes do not establish whole-system
refinement or verify the Tokio implementation.

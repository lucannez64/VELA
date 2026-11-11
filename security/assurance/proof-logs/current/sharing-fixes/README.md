# Sharing-boundary fixes, 2026-10-23

Implementation baseline: `148ff3261b62bd60df0d99d354e093500779fdce` plus the
source changes identified by the package manifest. These are local results;
no new GitHub Actions success or independent audit is asserted.

Command (one build/test worker, 3 GiB process-tree cgroup, zero swap):

```bash
security/assurance/bounded.sh env CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm \
  cargo +nightly test --manifest-path desktopVELA/Cargo.toml \
  -p vela-desktop-core --locked --lib
```

`desktop-core-tests.log` records the complete desktop-core unit suite:
**464 passed, zero failures, eight existing ignored tests**. The compiler emits
existing warnings; this is not a warning-free build.
The `sharing::assurance_boundary_review` module contains 13 new regression
tests, including the three previously unsafe behaviors, both interruption
checkpoints for acceptance and linked updates, concurrent acceptance, corrupt
and unreadable storage, missing payloads, legacy store migration, preservation
of later local edits/deletions, offline listing and pending-commit RMS rotation.
The three original share forgery/replay/serialization tests also run.

The failure checkpoints return an error after the actual durable journal or
vault write, then tests reopen the files through a new Store. This is fault
injection, not an OS power-failure test or a formal filesystem proof. The
old diagnostic witnesses remain in `../boundary-review/` as historical evidence
against the pre-fix source. The current tests assert safe behavior instead.

The new CI `sharing-boundaries` job runs this suite with the pinned security
CI Rust version; the local run uses the installed nightly recorded in
`versions.txt`. CI reproduction remains pending.

`desktop-core-flaky-test-before-fix.log` preserves an intermediate run that
failed the old `identity_keys_roundtrip_encrypted` first-byte assertion. A random
AEAD nonce began with `{`. The test now checks that the complete file cannot
be parsed as plaintext identity JSON, alongside the existing successful
correct-key round trip and wrong-key rejection. The final full run above passed.

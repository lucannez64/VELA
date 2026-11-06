# Recovery fact-construction increment

The delegated source commit be891d7 was integrated as 2641e01 on top of
4cc4dd6. Parent review additionally replaced unconditional challenge storage
with atomic insert-if-absent and a real-store interleaving regression.

`fstar.log` records fresh hax extraction and successful F★ checking of all
42 recovery contracts, including the 21 new observation/epoch/composition/
rejection contracts. Its five unit and three observation-enumeration tests
passed. The exact extraction snapshot here matches the source-tree output;
no generated body was changed. The current combined inventory is 173 explicit
postconditions / 180 directly selected functions, with seven selected spec/
comparison functions lacking ensures and zero local assume val declarations.
Other unchanged modules retain the earlier hosted evidence.

`atomic-insertion-test.log` records one passing real-store regression: two
requests observe an empty slot; the first stores its challenge, the second
receives Conflict and cannot replace the winner. `integration-tests.log` records
13 passing recovery tests, including the new missing-share and credential
availability cases. These finite tests do not prove every handler/database trace.

Proof commands used the shared vela-heavy lock, the 3 GiB/no-swap/one-worker
cap and the existing pinned hax 0.3.7 / Rust nightly-2025-11-08 / F★ 2025.10.06 /
Z3 4.13.3 tools. The local tools were already installed; no installer was run.
Normal Rust tests used the host nightly and explicit LLVM backend. To avoid a
cold dependency rebuild, the parent reused the completed delegate's target
directory through CARGO_TARGET_DIR; Cargo compiled the current parent sources,
as shown by the compilation paths in the logs. Heavy commands remained serial.

Portable commands from the repository root, with pinned tools activated:

```bash
security/assurance/bounded.sh serverVELA/vela-recovery-policy/verify-fstar.sh
security/assurance/bounded.sh cargo test --locked --manifest-path serverVELA/Cargo.toml -p vela-server --lib recovery::initiate::tests
security/assurance/bounded.sh cargo test --locked --manifest-path serverVELA/Cargo.toml -p vela-server --test integration recovery_
python3 security/assurance/check-proof-boundary.py
python3 security/formal/check-correspondence.py
```

[The exact boundary](../../../13-recovery-fact-refinement.md) includes unverified
SQL/store/WebAuthn origins and early returns. Epoch normalization retains the
legacy missing/non-positive fallback; it does not prove stale-epoch rejection.
The CAS operation's atomicity is trusted. No complete I/O/native/protocol or
full-system theorem is claimed. Hosted reproduction remains pending.

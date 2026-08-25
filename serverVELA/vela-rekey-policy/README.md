# Verified rekey policy

This crate is the pure production policy used by the server's vault-write and
rekey-lifecycle paths. Tamarin proves the protocol-level M11/M11c properties; hax extracts
these Rust decisions to F* so their source implementation, integer behavior,
and postconditions are checked for every input.

The proof boundary deliberately excludes HTTP parsing, Turso queries and
transaction atomicity. Those remain covered by the real-handler state-model
and race tests. The server converts authenticated/database comparisons into
`RekeyState`, `EpochRoute`, readiness facts, completeness witnesses, and
`AttemptAuthority`, then acts on this crate's
decision.

| Production decision | Universally checked property |
|---|---|
| `resolve_write_epoch` | Accepted writes use exactly the current or next epoch required by the phase; invalid and overflowing states reject. |
| `authorize_shadow` | A shadow write is allowed exactly for the active attempt's device, starter, rotation ID, and `N -> N+1` route. |
| `plan_start` | Start requires ACTIVE state, no ORAM, capable and fully acknowledged devices, and returns the exact representable successor. |
| `plan_commit` | Commit requires attempt authority plus both chunk-shadow and device-capsule completeness, and advances exactly once. |
| `plan_abort` / `plan_timeout` | Both terminal rollback paths preserve the authoritative epoch. |
| `authorize_commit_replay` | Lost-response success is allowed only for the exact recorded attempt and committed epoch. |
| `plan_active_mutation` | Vault, recovery, and enrollment requests receive an unforgeable permit only when declared and authenticated authority epochs agree and the authority class is valid for that mutation. |
| `authorize_active_mutation` | The permit is valid at the database boundary exactly when the account is ACTIVE at the permit epoch. |
| `stale_permit_authorizes_successor` | An ACTIVE(N) permit can never authorize ACTIVE(N+1), including at the integer boundary. |

## Install the pinned toolchain

hax 0.3.7 uses Rust nightly 2025-11-08. Install its compiler components and
both hax executables with the same toolchain:

```bash
rustup toolchain install nightly-2025-11-08 \
  --component rustc-dev \
  --component llvm-tools-preview \
  --component rust-analysis \
  --component rust-src \
  --component rustfmt

cargo +nightly-2025-11-08 install cargo-hax \
  --version 0.3.7 --locked
cargo +nightly-2025-11-08 install hax-driver \
  --version 0.3.7 --locked
```

Keep the OCaml hax engine and F* in separate opam switches. Their build-time
PPX constraints conflict even though the two executables work together at
runtime. First install the engine:

```bash
opam switch create vela-hax 5.1.1
git clone --depth 1 --branch cargo-hax-v0.3.7 \
  https://github.com/cryspen/hax.git hax-0.3.7
cargo +nightly-2025-11-08 install --locked \
  --path ./hax-0.3.7/engine/names/extract
opam install --switch vela-hax --yes ./hax-0.3.7/engine
```

Then install the F* version pinned by hax 0.3.7 in its own switch:

```bash
opam switch create vela-fstar 5.1.1
opam install --switch vela-fstar --yes fstar.2025.10.06
```

F* 2025.10.06 expects Z3 4.13.3. On Linux x86-64 with glibc 2.35 or
newer, install the official release binary under the versioned name F* looks
for:

```bash
curl -fLO https://github.com/Z3Prover/z3/releases/download/z3-4.13.3/z3-4.13.3-x64-glibc-2.35.zip
unzip z3-4.13.3-x64-glibc-2.35.zip
install -Dm755 z3-4.13.3-x64-glibc-2.35/bin/z3 ~/.local/bin/z3-4.13.3
```

Expose both executables in each shell that runs proofs:

```bash
export PATH="$(opam var bin --switch vela-hax):$(opam var bin --switch vela-fstar):$HOME/.local/bin:$PATH"
```

Verify the installation:

```bash
cargo hax --version
command -v hax-engine
fstar.exe --version
z3-4.13.3 --version
```

## Run

From this directory:

```bash
export PATH="$(opam var bin --switch vela-hax):$(opam var bin --switch vela-fstar):$HOME/.local/bin:$PATH"
./verify-fstar.sh
```

The runner first executes the Rust unit tests, then extracts the twelve production
policy entry points and asks F* to discharge their postconditions without
`--lax`.

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

## Executor honesty (F-1)

The driver proofs above assume each executor is honest: the observation it
returns is the truth about what its SQL and store writes did. F-1 removes that
assumption for the vault, rotation, ORAM, capsule and schema executors.

`src/executor.rs` splits every executor method into three pure pieces:

- `plan_*`: the method's inputs -> typed statements (`VaultStmt`: reads,
  guarded inserts/updates/deletes, version CAS, the shadow upsert, the account
  key-row CAS, completeness probes, bulk deletes, the schema store write,
  `Commit`);
- `render`: each statement -> the exact SQL text and typed parameters (or the
  exact store key), pinned byte for byte by unit tests;
- `classify_*`: the per-statement outcomes -> the observation the driver
  consumes.

`vela-server/src/vault/sql.rs` is the thin loop the executors now run: plan,
render, run each statement in order, stop at the first failure, classify.
`src/executor_model.rs` is the Rust mirror of the F* model.

`proofs/fstar/executor-lemmas/Vela_rekey_policy_executor_model.fst` models
`vault_chunks` (keyed by user, chunk id and epoch), `users` (the epoch and
attempt columns), `devices` (revoked, capability, capsule), `oram_buckets` and
the one schema key:

- a guarded `INSERT` inserts only when its `users` guard holds, and only then
  can the unique key conflict; a guarded `UPDATE`/`DELETE` changes the one
  matching row, or none, and reports how many; a version CAS matches only the
  stored version; the shadow upsert inserts or bumps `version`;
- `run_auto` (pool) and `run_tx` (a transaction publishes only at `Commit`);
  `cas_tx` is the shape of the freeze and abort transactions: the CAS, then
  the rest of the plan only when it changed the row, published by the plan's
  own `Commit`;
- `f = Some k` fails the k-th statement, including a commit;
- the two account-CAS statements carry the database's answers to their
  `NOT EXISTS` sub-queries (`answers`); `freeze_guard_is_honest` and
  `commit_guard_is_honest` state exactly what it means for those answers to be
  the truth.

`Vela_rekey_policy_executor_lemmas.fst` proves, for every starting database and
every fault point: success iff the guard held and no statement failed; on
success exactly the intended rows/keys changed; on failure the state is
unchanged; each point read observation equals the stored truth; and the facts
the drivers rely on (a committed write needs an ACTIVE account at the permit
epoch, a shadow write only lands inside the live attempt, an ACK clears only
its own epoch, a commit publishes a shadow for every old chunk and a capsule
for every active device, a rollback discards the attempt's shadows and
capsules, a freeze only starts on a clean account).

The five completeness probes and the inventory row set are `EXISTS`/multi-row
queries over the id space. A functional table cannot decide or enumerate them,
so their answers are inputs to the model; `classify_probe`/`classify_inventory`
are proved to report exactly the store's answer, and the bounded real-database
conformance test (`vela-server/src/vault/conformance.rs`) checks those answers
and the rendered predicates against turso on small states, with a fault
injected at every statement, commit and store write.

`verify-fstar-vault-executors.sh` extracts the plans and classifiers, checks
each proof module in its own process, and runs
`verify-fstar-vault-executors-mutations.sh`: a classifier reporting a failed
delete/update/ACK as success, a plan that swaps the capsule target, a plan that
drops the transaction commit, and a model that ignores the account-epoch guard
must each break a named theorem.
